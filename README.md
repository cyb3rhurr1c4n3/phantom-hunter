<div align="center">

# 🔍 Phantom Hunter

### _An Advanced Malware Detector Targeting Process Injection Techniques_

[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-blue?style=for-the-badge&logo=windows&logoColor=white)]()
[![Language](https://img.shields.io/badge/language-C%2B%2B17-lightgrey?style=for-the-badge&logo=cplusplus)]()
[![Status](https://img.shields.io/badge/status-v1.0-brightgreen?style=for-the-badge)]()
[![MITRE](https://img.shields.io/badge/MITRE-T1055.003%20%7C%20T1055.012-orange?style=for-the-badge)]()

**[Overview](#-overview)** •
**[How It Works](#-how-it-works)** •
**[Detection Logic](#-detection-logic)** •
**[Installation](#-installation--build)** •
**[Usage](#-usage)** •
**[Limitations](#-limitations--known-gaps)**

</div>

---

## 📋 Overview

**Phantom Hunter** is a Windows-native malware detector focused on identifying **process injection techniques** - specifically techniques that abuse thread context manipulation to execute arbitrary code under the identity of a legitimate host process.

The tool was developed as the defensive counterpart to **Phantom Hollowing**, a custom process injection technique that combines Process Hollowing (T1055.012) and Thread Execution Hijacking (T1055.003) while deliberately removing the `NtUnmapViewOfSection` step to reduce its detection surface. Phantom Hunter was built with full knowledge of that technique's internals - making the detection logic precise and purpose-built rather than generic.

**Detection approach:** Rather than relying on a single indicator, Phantom Hunter uses a **hybrid static/dynamic analysis pipeline** with a weighted behavioral scoring system. Multiple low-confidence signals combine into a high-confidence verdict, reducing false positives while catching techniques that evade signature-only or behavior-only detectors.

> **Legal Notice**: Phantom Hunter is intended for use on systems you own or have explicit written authorization to analyze. The authors assume no responsibility for misuse.

---

## 🧠 How It Works

### Core insight: RIP → MEM_PRIVATE

The fundamental detection primitive in Phantom Hunter targets an unavoidable artifact of any Thread Context Hijacking-based injection:

```
Normal process:
  Thread RIP → MEM_IMAGE region (backed by a PE file on disk)
               └── mbi.Type: MEM_IMAGE ✅

Injected process:
  Thread RIP → MEM_PRIVATE region (allocated via VirtualAlloc / NtAllocateVirtualMemory)
               └── mbi.Type: MEM_PRIVATE ⚠️ CRITICAL INDICATOR
```

Any technique that injects shellcode into dynamically allocated memory and redirects thread execution via `SetThreadContext` / `NtSetContextThread` **cannot avoid** this artifact - the instruction pointer will always point into a `MEM_PRIVATE` region rather than a legitimate `MEM_IMAGE` region. This is the highest-confidence single indicator in Phantom Hunter's scoring model, and it applies equally to Process Hollowing (T1055.012) and Thread Execution Hijacking (T1055.003).

### Scoring System

Every indicator contributes a weighted score. The aggregate determines the verdict:

```
┌──────────────────────────────────────────────────────────────┐
│                      SCORING MODEL                           │
├──────────────────────────────────────────────────────────────┤
│  Static Analysis                                             │
│  ├── Multiple critical NT APIs (3+)          → +35 pts       │
│  ├── Single critical NT API + support (3+)   → +25 pts       │
│  ├── Single critical NT API (standalone)     → +15 pts       │
│  ├── Support/suspicious APIs only (2+)       → +10 pts       │
│  ├── Shannon entropy > 7.8 (very high)       → +30 pts       │
│  ├── Shannon entropy ≥ 7.5 (high)            → +20 pts       │
│  ├── Invalid / tampered signature            → +40 pts       │
│  ├── Not signed                              → +25 pts       │
│  └── Third-party signed (valid)              → +20 pts       │
│     (Microsoft-signed binaries score 0 pts)                  │
│                                                              │
│  Dynamic Analysis                                            │
│  ├── Thread Context Hijacking (RIP→MEM_PRIV) → +60 pts ⚠️   │
│  ├── Known payload signature in memory       → +50 pts       │
│  ├── Suspended thread duration > 10s         → +35 pts       │
│  ├── Suspended thread duration > 5s          → +20 pts       │
│  └── Network anomaly (unsafe process)        → +15 pts       │
├──────────────────────────────────────────────────────────────┤
│  Verdict Thresholds                                          │
│  ├── Score < 60      → CLEAN        (no action needed)       │
│  ├── 60 ≤ Score < 120 → SUSPICIOUS  (investigate)           │
│  └── Score ≥ 120     → MALWARE      (quarantine immediately) │
└──────────────────────────────────────────────────────────────┘
```

---

## 🔬 Detection Logic

### Static Analysis

**1. NT API String Detection**

Phantom Hollowing and similar techniques resolve NT API functions at runtime via `GetProcAddress`. This means the function name strings remain in the binary's `.rdata` section and are recoverable through static scanning - regardless of whether the binary uses dynamic loading to avoid IAT entries.

Monitored critical NT APIs:

| API                       | Role in injection                         |
| ------------------------- | ----------------------------------------- |
| `NtAllocateVirtualMemory` | Allocate RW memory in the remote process  |
| `NtWriteVirtualMemory`    | Write shellcode into the allocated region |
| `NtProtectVirtualMemory`  | Transition memory from RW → RX            |
| `NtGetContextThread`      | Read the host thread's register state     |
| `NtSetContextThread`      | **Redirect RIP/EIP to shellcode**         |
| `NtResumeThread`          | Trigger execution                         |
| `NtQueryVirtualMemory`    | Query memory region properties            |

Scoring is cumulative based on the number and combination of strings found (see scoring table above).

> **Bypass caveat**: API hashing eliminates these strings from the binary. If an injector resolves NT APIs via a custom hash-based resolver, this indicator will not fire. Entropy scoring and dynamic analysis compensate for this gap.

**2. Shannon Entropy**

Obfuscation and encryption raise a file's entropy. This creates a useful trade-off for detection: a binary that hides its NT API strings through obfuscation will likely exhibit elevated entropy, which Phantom Hunter scores as a separate signal.

```
H(X) = -Σ[i=0..255] P(i) × log₂(P(i))     range: [0, 8] bits/byte

  H > 7.8  → +30 pts  (likely packed or encrypted)
  H ≥ 7.5  → +20 pts  (suspicious, possible obfuscation)
  H < 7.5  → 0 pts    (normal range for compiled binaries)
```

**3. Digital Signature Verification**

Uses the Windows `WinVerifyTrust` API:

| Result                        | Score   | Notes                              |
| ----------------------------- | ------- | ---------------------------------- |
| Valid - Microsoft Corporation | +0 pts  | Fully trusted                      |
| Valid - third-party           | +20 pts | Legitimate but not a system binary |
| Not signed                    | +25 pts | Common for custom/malicious tools  |
| Invalid / tampered            | +40 pts | Strong indicator of compromise     |

---

### Dynamic Analysis

**1. Thread Context Hijacking Detection** _(Primary indicator - +60 pts)_

For every thread in every scanned process:

```
1. OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION)
2. GetThreadContext(&ctx)  →  extract ctx.Rip (x64) or ctx.Eip (x86)
3. VirtualQueryEx(hProcess, ip, &mbi)  →  query the memory region at IP
4. if (mbi.Type == MEM_PRIVATE &&
       (mbi.Protect == PAGE_EXECUTE_READ ||
        mbi.Protect == PAGE_EXECUTE_READWRITE))
       → THREAD CONTEXT HIJACKING DETECTED (+60 pts)
```

This check is **technique-agnostic**: it catches any injection variant that redirects thread execution into dynamically allocated memory, including Process Hollowing, Thread Execution Hijacking, and Phantom Hollowing. The `MEM_PRIVATE` type is an OS-level property of how memory was allocated - the malware cannot change it after injection.

**2. Memory Signature Scanning** _(+50 pts)_

Enumerates all memory regions with `MEM_PRIVATE` type and execute permissions, then searches for known payload signatures:

- **Metasploit Meterpreter** - stage encoding patterns, reverse shell structures
- **Cobalt Strike Beacon** - beacon configuration blocks, sleep mask patterns, HTTP C2 headers
- **Generic shellcode heuristics** - `GetProcAddress` call patterns, socket API sequences

This catches the **decrypted payload in memory** after injection completes, regardless of how it was encrypted on disk.

**3. Suspended Thread Duration** _(+20–35 pts)_

Flags processes whose main thread remains in a suspended state for an abnormally long duration. Phantom Hollowing uses `CREATE_SUSPENDED` combined with `Sleep()` calls for sandbox evasion - the process stays suspended for 5–10+ seconds before `NtResumeThread` is called.

```
Suspended > 5s   → +20 pts
Suspended > 10s  → +35 pts
```

False positive mitigation: debuggers (`x64dbg.exe`, `windbg.exe`, `devenv.exe`) and process analysis tools (`procexp.exe`, `Processhacker.exe`) are whitelisted. Parent process context is also checked.

**4. Network Anomaly Detection** _(+15 pts - supporting indicator)_

Flags processes that have no legitimate reason to establish network connections but are found with active TCP sessions. Common injection targets in this category: `notepad.exe`, `calc.exe`, `mspaint.exe`, `write.exe`.

This is intentionally a low-weight supporting indicator. Its main value is **constraining the attacker's target selection**: using a network-capable process like `explorer.exe` or `conhost.exe` as the host avoids this flag, but those processes are more actively monitored by other heuristics.

---

### Whitelist Handling

System processes (`svchost.exe`, `explorer.exe`, `csrss.exe`, `lsass.exe`, `services.exe`, `winlogon.exe`, `smss.exe`, `wininit.exe`) skip suspended-thread and network anomaly checks to avoid false positives from their normal behavior. **Thread hijacking detection still runs against them** - these are among the most common injection targets and cannot be excluded from the primary check.

JIT-compiling runtimes (`dotnet.exe`, `java.exe`) are excluded from the `MEM_PRIVATE` thread check, since JIT compilation legitimately produces executable private memory regions.

---

## 📦 Installation & Build

### Requirements

| Component    | Requirement                                              |
| ------------ | -------------------------------------------------------- |
| OS           | Windows 10/11 x64                                        |
| IDE          | Visual Studio 2022                                       |
| Compiler     | MSVC v143+                                               |
| Windows SDK  | 10.0.19041.0 or later                                    |
| Architecture | x64 (required - reads the 64-bit RIP register)           |
| Privileges   | Administrator (required for cross-process memory access) |

### Build Configuration

**Visual Studio 2022:**

```
Configuration:   Release
Platform:        x64

C/C++:
  Optimization:        /O2
  Runtime Library:     /MT  ← static linking; no VC++ Redistributable dependency
  C++ Standard:        /std:c++17
  Warning Level:       /W4

Linker → Additional Dependencies:
  psapi.lib       ← process enumeration
  advapi32.lib    ← token/privilege APIs
  wintrust.lib    ← WinVerifyTrust
  crypt32.lib     ← certificate chain APIs
  iphlpapi.lib    ← TCP table for network anomaly check
  ws2_32.lib      ← Winsock
```

### Build Steps

```batch
# Option 1: Visual Studio GUI
# Open Phantom_Hunter.sln → Release / x64 → Build Solution (Ctrl+Shift+B)

# Option 2: MSBuild
msbuild Phantom_Hunter.sln /p:Configuration=Release /p:Platform=x64

# Option 3: Direct cl.exe
cl.exe /EHsc /O2 /MT /std:c++17 phantom_hunter_detector.cpp ^
  /link psapi.lib advapi32.lib wintrust.lib crypt32.lib iphlpapi.lib ws2_32.lib ^
  /out:Phantom_Hunter.exe
```

### Project Structure

```
phantom-hunter/
├── phantom_hunter_detector.cpp    # Main source
├── phantom_hunter_config.h        # Scoring weights and configuration constants
├── Phantom_Hunter.sln
├── Phantom_Hunter.vcxproj
└── x64/Release/
    └── Phantom_Hunter.exe
```

---

## 📖 Usage

> ⚠️ **Administrator privileges required** for all dynamic analysis modes (`--scan`, `--monitor`). Phantom Hunter requires `OpenProcess`, `ReadProcessMemory`, `VirtualQueryEx`, and `GetThreadContext` access across processes.

```batch
Phantom_Hunter.exe --help                    # Show usage
Phantom_Hunter.exe <path\to\file.exe>        # Static file analysis
Phantom_Hunter.exe --scan                    # Snapshot scan of all running processes
Phantom_Hunter.exe --monitor                 # Continuous real-time monitoring
```

### Mode 1 - File Analysis

Static analysis only. No process access required.

```
> Phantom_Hunter.exe C:\samples\suspect.exe

[+] ========== STATIC ANALYSIS ==========
[*] Analyzing: C:\samples\suspect.exe
[!] Critical NT API: NtAllocateVirtualMemory
[!] Critical NT API: NtWriteVirtualMemory
[!] Critical NT API: NtSetContextThread
[*] Entropy: 5.87 / 8.0  (normal)
[!] File not digitally signed

[+] =========== VERDICT ==================
Score:      60.0
Indicators: Multiple critical NT APIs (3+) | Not signed
Verdict:    [!] SUSPICIOUS - INVESTIGATE
```

### Mode 2 - Quick Scan (Snapshot)

Full pipeline against all currently running processes.

```
> Phantom_Hunter.exe --scan

[+] ========== DYNAMIC ANALYSIS ==========
[*] Scanning 156 active processes...

[DETECT] ==========================================
[DETECT] Thread Context Hijacking detected!
[DETECT] Process: conhost.exe  PID: 12456
[DETECT] RIP: 0x000001A2B3C4D000 → MEM_PRIVATE
[DETECT] ==========================================

[+] =========== VERDICT ==================
Score:      75.0
Indicators: Thread Context Hijacking (RIP→MEM_PRIVATE) | Network anomaly
Verdict:    [!] SUSPICIOUS - INVESTIGATE
Affected:   PID 12456 (conhost.exe)
```

### Mode 3 - Continuous Monitor

Polls the process list every second. New processes are scanned immediately on detection.

```
> Phantom_Hunter.exe --monitor

[+] Baseline: 158 processes. Monitoring started. Press Ctrl+C to stop.

[!] NEW PROCESS: suspicious.exe  PID: 15678
    Score:      110.0
    Indicators: Thread Context Hijacking | Metasploit signature in memory
    Verdict:    [!] SUSPICIOUS - INVESTIGATE

^C
[*] Monitor stopped. Total scans performed: 127.
```

### Before / After - Phantom Hollowing

**Before injection:**

```
[+] Scanned 156 processes. Score: 0.0 - CLEAN. No suspicious indicators found.
```

**After Phantom Hollowing executes against conhost.exe:**

```
[DETECT] conhost.exe (PID: 23456): RIP → MEM_PRIVATE  ⚠️
[DETECT] conhost.exe (PID: 23456): Network-unsafe process has active TCP connection

Score:   75.0
Verdict: [!] SUSPICIOUS - INVESTIGATE
```

---

## ⚠️ Limitations & Known Gaps

| Limitation                                | Impact | Notes                                                                                                                                                                                                                                   |
| ----------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **API hashing bypass**                    | Medium | If the injector resolves NT APIs via a custom hash resolver, string scanning produces 0 pts; entropy + dynamic checks compensate                                                                                                        |
| **JIT false positives**                   | Low    | .NET/Java JIT compilation produces `MEM_PRIVATE` executable regions; mitigated via process whitelist                                                                                                                                    |
| **Polling gap in monitor mode**           | Medium | Processes that spawn and terminate in under 1 second may not be caught                                                                                                                                                                  |
| **Phantom Hollowing v2 partial coverage** | Medium | v2 plans to remove `CREATE_SUSPENDED` (replaced with `OpenThread`→`SuspendThread` on a running process) and add API hashing - the suspended-thread and string indicators will not fire, but **RIP→MEM_PRIVATE detection still applies** |
| **No kernel-level visibility**            | High   | Direct syscalls, kernel driver injection, or ETW patching can circumvent all userland detection; this tool operates entirely in user mode                                                                                               |
| **Payload signature coverage**            | Medium | Currently covers Metasploit Meterpreter and Cobalt Strike Beacon; custom or unknown payloads rely on heuristic scoring only                                                                                                             |

---

## 🗺️ Roadmap

### v1.1

- [ ] YARA rule integration for extensible payload signature matching
- [ ] Configurable whitelist via external file
- [ ] JSON output for SIEM/logging pipeline integration

### v1.2

- [ ] Memory dump export for flagged processes (for offline forensic analysis)
- [ ] Updated coverage for Phantom Hollowing v2: API hashing variants and `OpenThread`-based suspension
- [ ] Detection coverage for DLL Hollowing (Load-and-Stomp) - planned in Phantom Hollowing v3

### Long-term

- [ ] Kernel driver mode using ETW and kernel callbacks for bypass-resistant detection
- [ ] ML-based classifier for unknown shellcode patterns in executable private memory

---

## 📚 References

- [MITRE ATT&CK T1055.003 - Thread Execution Hijacking](https://attack.mitre.org/techniques/T1055/003/)
- [MITRE ATT&CK T1055.012 - Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)
- [Windows NT API Reference](https://ntdoc.m417z.com/)
- [Phantom Hollowing](https://github.com/cyb3rhurr1c4n3/phantom-hollowing) - The injection technique this detector was built against

---

## ✍️ Author

**Võ Quốc Bảo** ([@cyb3rhurr1c4n3](https://github.com/cyb3rhurr1c4n3))

---

<div align="center">

**Phantom Hunter** - Built by [@cyb3rhurr1c4n3](https://github.com/cyb3rhurr1c4n3) · UIT, Vietnam · 2025

</div>
