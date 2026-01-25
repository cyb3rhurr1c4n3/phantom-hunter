### 1 - Các ý tưởng ban đầu và tại sao thất bại

#### 1.1 Phân tích tĩnh

**a) Dựa vào payload msfvenom**

- **Ý tưởng**: Detect signature của payload Metasploit trong file
- **Vấn đề**: Payload được mã hóa bằng XOR Encryption với key bất kỳ nên rất khó bắt được
- **Kết luận**: Không khả thi cho static analysis
- **Lưu ý**: Tuy nhiên có thể áp dụng cho **dynamic analysis** khi payload đã được giải mã trong RAM
  **b) Dựa vào hàm giải mã**
- **Ý tưởng**: Dù payload được mã hóa thì hàm giải mã vẫn ở dạng plain text
- **Vấn đề**: Phantom Hollowing sử dụng XOR Decryptor đơn giản (1 vòng lặp for với XOR), thứ được dùng bởi nhiều phần mềm giải nén file, ảnh, game engines
- **Kết luận**: Gây False Positive cực cao
- **Ví dụ False Positive**: WinRAR, 7-Zip, game engines sử dụng XOR cho data obfuscation
  **c) Bruteforce XOR key**
- **Ý tưởng**: Với các vùng dữ liệu lạ, thử bruteforce XOR với key 1 byte (256 possibilities) để xem có payload phổ biến nào được phát hiện không
- **Vấn đề**:
    - Performance overhead (256 attempts per data section)
    - Dễ dàng bị bypass bằng cách tăng độ dài XOR Key (2 bytes = 65536 combinations, 4 bytes = 4 billion)
    - Multi-byte XOR hoặc stream ciphers (RC4, ChaCha20) làm bruteforce không khả thi
- **Kết luận**: Không scalable và dễ bypass
  **d) Detect NT API import table**
- **Ý tưởng**: Kiểm tra Import Address Table (IAT) cho NT APIs
- **Vấn đề**: Phantom Hollowing dùng **dynamic loading** (`GetProcAddress`) nên NT APIs không xuất hiện trong IAT
- **Kết luận**: Không hiệu quả với dynamic API resolution

#### 1.2 Phân tích động

**a) Process được tạo ở trạng thái SUSPENDED**

- **Ý tưởng**: Flag tất cả processes tạo với `CREATE_SUSPENDED` flag
- **Vấn đề**: Nhiều phần mềm hợp pháp cũng tạo suspended processes:
    - **.NET Framework** (JIT compilation setup)
    - **Windows Error Reporting** (crash dump collection)
    - **Debuggers** (x64dbg, WinDbg, Visual Studio)
    - **Antivirus software** (process scanning)
    - **Process Hacker, Process Explorer** (analysis tools)
- **Kết luận**: Không đủ làm indicator duy nhất, chỉ nên dùng làm **yếu tố phụ trợ**
  **b) Monitor registry/file modifications**
- **Ý tưởng**: Detect persistence mechanisms (Registry Run keys, Startup folder)
- **Vấn đề**: Phantom Hollowing PoC không implement persistence, chỉ là in-memory execution
- **Kết luận**: Không áp dụng được cho kỹ thuật này
  **c) Detect API hooking**
- **Ý tưởng**: Monitor userland hooks (IAT/EAT hooking)
- **Vấn đề**: Phantom Hollowing dùng NT API, bypass userland defense
- **Kết luận**: Không khả thi

### 2 - Đề xuất giải pháp - Phantom Hunter

#### 2.1 Cách hoạt động

**Scoring System Architecture:**

```
┌─────────────────────────────────────────────┐
│         PHANTOM HUNTER SCORING              │
├─────────────────────────────────────────────┤
│                                             │
│  Static Analysis                            │
│  ├─ Suspiciuos API Strings → 15-35 points   │
│  ├─ High Entropy           → 20 points      │
│  └─ Not MS Signed          → 25 points      │
│                                             │
│  Dynamic Analysis                           |
│  ├─ Thread Hijacking    → 60 points         │
│  ├─ Suspended Process   → 20 points         │
│  ├─ Payload Signature   → 50 points         │
│  ├─ Network Anomaly     → 15 points         │
│  └─ ...                                     │
│                                             │
│  Total Score Calculation                    │
│  ├─ Score < 60      → CLEAN                 │
│  ├─ 60 ≤ Score < 120 → SUSPICIOUS           │
│  └─ Score ≥ 120      → MALWARE              │
└─────────────────────────────────────────────┘
```

**Nguyên lý:**

- Mỗi dấu hiệu/hành vi đáng ngờ được gán điểm khác nhau
- Điểm càng cao = độ tin cậy detection càng cao
- Tổng điểm vượt threshold → Flag là malware
- **Multi-factor approach** giảm false positives
  **Threshold for classification**

| Score Range | Verdict    | Action                 | Confidence     |
| ----------- | ---------- | ---------------------- | -------------- |
| 0-59        | CLEAN      | No action needed       | Low risk       |
| 60-119      | SUSPICIOUS | INVESTIGATE            | Medium risk    |
| 120+        | MALWARE    | QUARANTINE IMMEDIATELY | Very high risk |

#### 2.2 Phân tích tĩnh

**a) Dựa vào các string NT API và các API hỗ trợ**
**Nguyên lý:**

```cpp
// Phantom Hollowing PHẢI resolve NT APIs
HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
auto NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)
    GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
//                         ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑
//                    String này tồn tại trong binary!
```

**NT APIs nguy hiểm được monitor:**

1. `NtAllocateVirtualMemory` - Cấp phát memory trong remote process
2. `NtWriteVirtualMemory` - Ghi payload vào remote process
3. `NtGetContextThread` - Lấy thread context (RIP/EIP)
4. `NtSetContextThread` - **Hijack RIP/EIP** (⚠️ CRITICAL)
5. `NtResumeThread` - Resume suspended thread
6. `NtProtectVirtualMemory` - Đổi protection (RW → RX)
7. `NtQueryVirtualMemory` - Query memory info
8. Và một số API hỗ trợ phổ biến khác
   **Scoring Logic:**

```
Multiple support, suspicious API (2+): +10 points (không đáng kể)
Single critical NT API: +15 points (đáng ngờ nhẹ)
Single critical NT API & some support (3+): +25 points (trung bình)
Multiple critical NT APIs (3+): +35 points (khả năng cao injection)
```

**Tại sao hiệu quả:**

- ✅ Phantom Hollowing **BẮT BUỘC** phải dùng NT APIs
- ✅ Strings tồn tại trong .rdata section của PE
- ✅ Không thể bypass trừ khi dùng API hashing (phức tạp hơn nhiều)
  **Limitations:**
- ⚠️ Legitimate software cũng có thể dùng 1-2 NT APIs
- ⚠️ API hashing có thể bypass (nhưng phát hiện được qua entropy + behavior)

---

**b) Kiểm tra Entropy của file (Anti-Obfuscation)**
**Công thức Shannon Entropy:**

```
H(X) = -Σ[i=0 to 255] P(i) × log₂(P(i))

Trong đó:
  P(i) = frequency(byte_i) / total_bytes
  H(X) ∈ [0, 8] bits per byte
```

**Scoring:**

```
Entropy < 7.5:  xem như an toàn
Entropy >= 7.5:  +20 points (High)
Entropy > 7.8:  +30 points (Very High - likely obfuscated)
```

**Tại sao hiệu quả:**

- ✅ Dù obfuscate có thể giúp bypass string detection, nhưng sẽ vô tình làm tăng entropy
- ✅ Trade-off: Bypass strings → Tăng entropy → Vẫn bị detect
- ✅ Đa số malware phải chọn 1 trong 2: Visible strings HOẶC High entropy
  **Lưu ý:**
- Phantom Hollowing PoC không obfuscate → Entropy normal (~5.0-6.5)
- Nếu có variant obfuscated → Entropy cao → Vẫn bị phát hiện

---

**c) Kiểm tra chữ ký Microsoft (WinVerifyTrust)**
**Scoring:**

```
VALID_MICROSOFT:  0 points  (Fully trusted)
VALID_OTHER:     +20 points (Third-party, moderate suspicion)
NOT_SIGNED:      +25 points (No signature)
INVALID:         +40 points (Tampered signature!)
```

**Implementation:**

```cpp
switch (status) {
	case SignatureVerifier::VALID_MICROSOFT:
	    LOG_SUCCESS("File signed by Microsoft Corporation");
	    break;
	case SignatureVerifier::VALID_OTHER:
	    LOG_INFO("Valid signature (third-party)");
	    result.AddScore(Config::Score::StaticAnalysis::NOT_MICROSOFT_SIGNED, "Not Microsoft-signed");
	    break;
	case SignatureVerifier::INVALID:
	    LOG_ERROR("Invalid/tampered signature!");
	    result.AddScore(Config::Score::StaticAnalysis::INVALID_SIG, "Invalid signature");
	    break;
	case SignatureVerifier::NOT_SIGNED:
	    LOG_WARN("File not digitally signed");
	    result.AddScore(Config::Score::StaticAnalysis::NOT_SIGNED, "Not signed");
	    break;
	default:
	    LOG_ERROR("Signature verification error");
	    break;
}
```

**Tại sao hiệu quả:**

- ✅ Legitimate Windows tools đều Microsoft-signed
- ✅ Malware thường không sign (hoặc fake sign → detect được qua INVALID)
- ✅ Kết hợp với NT API strings → High confidence detection

---

#### 2.3 Phân tích động

**a) Process SUSPENDED lâu (Behavioral Anomaly)**
**Detection Logic:**

```cpp
// Check suspend duration
DWORD suspendCount = SuspendThread(hThread);
if (suspendCount > 0) {
    DWORD duration = GetTickCount() - processCreateTime;

    if (duration > 5000) {  // 5 seconds
        score += 20;  // Suspicious
    }
    if (duration > 10000) { // 10 seconds
        score += 35;  // Very suspicious
    }
}
ResumeThread(hThread);
```

**Tại sao Phantom Hollowing vulnerable:**

```cpp
// Trong Phantom Hollowing code:
Sleep(5000);  // ← Để tránh sandbox detection
MessageBoxA(...);  // Social engineering
Sleep(5000);  // ← Thêm delay nữa!
NtResumeThread(...);
```

→ Process suspended **10+ seconds** = Bất thường!
**Scoring:**

```
Suspended < 5s:       0 points (Normal)
Suspended 5-10s:    +20 points (Suspicious)
Suspended > 10s:    +35 points (Very suspicious)
```

**False Positive Mitigation:**

- Whitelist debuggers: WinDbg, x64dbg, Visual Studio,...
- Check parent process: Nếu parent là debugger → Ignore
- Analyze process name: ProcessHacker.exe, procexp.exe → Ignore

---

**b) Quét bộ nhớ để tìm payload signature (Memory Forensics)**
**Implementation:**

```cpp
// Scan all MEM_PRIVATE regions with EXECUTE permission
while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
    if (mbi.Type == MEM_PRIVATE &&
        (mbi.Protect & PAGE_EXECUTE_READ)) {

        // Read memory region
        unsigned char* buffer = new unsigned char[mbi.RegionSize];
        ReadProcessMemory(hProcess, mbi.BaseAddress, buffer,
                         mbi.RegionSize, &bytesRead);

        // Search for known signatures
        if (SearchMetasploitSignature(buffer, bytesRead)) {
            score += 50;  // PAYLOAD DETECTED!
        }
        if (SearchCobaltStrikeSignature(buffer, bytesRead)) {
            score += 50;
        }
        //...
    }
}
```

**Signatures được detect:**

1. **Metasploit Meterpreter**:
    - Header magic bytes
    - Stage encoding patterns
    - Reverse shell structures
2. **Cobalt Strike Beacon**:
    - Beacon configuration blocks
    - Sleep mask patterns
    - HTTP C2 headers
3. **Common Shellcode**: - GetProcAddress loops - WinExec/CreateProcess calls - Socket API sequences
   **Scoring:**

```
Metasploit detected:      +50 points
Cobalt Strike detected:   +50 points
Generic shellcode:        +30 points
```

**Tại sao hiệu quả:**

- ✅ Dù payload không bị phát hiện bằng static analysis (vì encrypted)
- ✅ Khi execute, **BẮT BUỘC** phải giải mã trong RAM
- ✅ Memory forensics bắt được payload dạng plain text

---

**c) Hành vi kết nối mạng bất thường (Network Anomaly)**
**Detection Logic:**

```cpp
// Network-unsafe processes
const char* NETWORK_UNSAFE[] = {
    "notepad.exe",
    "calc.exe",
    "mspaint.exe",
    "write.eexe
    //...
};

if (IsNetworkUnsafeProcess(processName)) {
    if (HasActiveConnections(pid)) {
        score += 15;  // Network anomaly!
    }
}
```

**Tại sao cần:**

- notepad.exe, calc.exe **KHÔNG BAO GIỜ** kết nối mạng normally
- Nếu có connection → Rõ ràng bị hijack/inject
  **Limitations:**
- ⚠️ Phantom Hollowing PoC dùng `conhost.exe`, `explorer.exe` (có network capability)
- ⚠️ Chỉ là **yếu tố phụ trợ** (+15 điểm), không phải primary detection
  **Vai trò:**
- Hạn chế attacker tùy ý chọn victim process
- Force attacker chọn processes có network capability → Dễ monitor hơn

---

**d) Thread Context Hijacking Detection (⭐⭐⭐ CRITICAL)**
**Core Detection Logic:**

```cpp
// 1. Get thread context
CONTEXT ctx = {0};
ctx.ContextFlags = CONTEXT_FULL;
GetThreadContext(hThread, &ctx);

// 2. Get instruction pointer
#ifdef _WIN64
    DWORD_PTR ip = ctx.Rip;
#else
    DWORD_PTR ip = ctx.Eip;
#endif

// 3. Query memory type
MEMORY_BASIC_INFORMATION mbi = {0};
VirtualQueryEx(hProcess, (LPCVOID)ip, &mbi, sizeof(mbi));

// 4. CHECK CRITICAL CONDITION
if (mbi.Type == MEM_PRIVATE &&
    (mbi.Protect == PAGE_EXECUTE_READ ||
     mbi.Protect == PAGE_EXECUTE_READWRITE)) {

    // ⚠️⚠️⚠️ PHANTOM HOLLOWING DETECTED! ⚠️⚠️⚠️
    score += 60;  // CRITICAL INDICATOR
}
```

**Tại sao đây là "Khắc tinh" của Phantom Hollowing:**
**Normal Process:**

```
┌─────────────────────────────────────┐
│ Thread Execution                     │
│                                      │
│ RIP: 0x7FF1234000                   │
│  │                                   │
│  v                                   │
│ ┌──────────────────────────┐        │
│ │ notepad.exe (MEM_IMAGE)  │ ← Code │
│ │ Protection: PAGE_EXECUTE_READ│     │
│ │ Type: MEM_IMAGE          │        │
│ └──────────────────────────┘        │
│                                      │
│ Legitimate: Code từ PE file         │
└─────────────────────────────────────┘
```

**Phantom Hollowing Process:**

```
┌─────────────────────────────────────┐
│ Thread Execution                     │
│                                      │
│ RIP: 0x1A2B3C4000 (HIJACKED!)      │
│  │                                   │
│  v                                   │
│ ┌──────────────────────────┐        │
│ │ Allocated Memory         │ ← Payload│
│ │ Type: MEM_PRIVATE ⚠️     │        │
│ │ Protection: PAGE_EXECUTE_READ│     │
│ │ [MALICIOUS SHELLCODE]    │        │
│ └──────────────────────────┘        │
│                                      │
│ ┌──────────────────────────┐        │
│ │ conhost.exe (MEM_IMAGE)  │        │
│ │ (Never executed!)        │        │
│ └──────────────────────────┘        │
│                                      │
│ DETECTED: RIP → MEM_PRIVATE!        │
└─────────────────────────────────────┘
```

**Phantom Hollowing PHẢI:**

1. ✅ Allocate memory: `NtAllocateVirtualMemory` → Type = `MEM_PRIVATE`
2. ✅ Write payload: `NtWriteVirtualMemory`
3. ✅ Change protection: `NtProtectVirtualMemory` → `PAGE_EXECUTE_READ`
4. ✅ Hijack RIP: `NtSetContextThread` → RIP trỏ vào MEM_PRIVATE
5. ✅ Execute: `NtResumeThread`
   --> **KHÔNG THỂ TRÁNH ĐƯỢC** việc RIP trỏ vào MEM_PRIVATE!
   --> Đây cũng là khắc tinh của Process Hollowing và Thread Execution Hijacking vì cả 2 đều thực hiện bước này
   **Scoring:**

```
RIP → MEM_PRIVATE + PAGE_EXECUTE_READ:  +60 points ⚠️ CRITICAL
```

**Tại sao +60 điểm (highest single indicator):**

- ✅ **Độ tin cậy cực cao** (95%+ confidence)
- ✅ **Không thể bypass** - Bản chất kỹ thuật yêu cầu MEM_PRIVATE
- ✅ **Low false positive** - Legitimate software KHÔNG BAO GIỜ execute từ MEM_PRIVATE
  **Possible False Positives (Rare):**
- JIT compilers (.NET, Java) - **Mitigated**: Whitelist `dotnet.exe`, `java.exe`
- Debugging tools - **Mitigated**: Check parent process
- Legitimate code injection (antivirus) - **Mitigated**: Check digital signature

### 3 - Giải pháp hoàn chỉnh

```
┌─────────────────────────────────────────────────────┐
│                  PHANTOM HUNTER                     │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌──────────────┐   ┌────────────────────────────┐  │
│  │  FILE        │   │  PROCESS   +   CONTINUOUS  │  │
│  │  ANALYZER    │   │  MONITOR        MONITOR    │  │
│  └──────┬───────┘   └──────┬─────────────────────┘  │
│         │                  │                        │
│         ▼                  ▼                        │
│  ┌──────────────┐   ┌──────────────┐                │
│  │  • NT APIs   │   │  • Thread    │                │
│  │  • Entropy   │   │    Hijacking │ ← CRITICAL     │
│  │  • Signature │   │  • Suspended │                │
│  └──────┬───────┘   │  • Memory    │                │
│         │           │  • Network   │                │
│         │           └──────┬───────┘                │
│         │                  │                        │
│         └────────┬─────────┘                        │
│                  ▼                                  │
│         ┌────────────────┐                          │
│         │ SCORING ENGINE │                          |
│         └────────┬───────┘                          │
│                  ▼                                  │
│         ┌────────────────┐                          │
│         │    VERDICT     │                          │
│         │   GENERATOR    │                          │
│         │ -------------- │                          │
│         │ CLEAN?         │                          │
│         │ SUSPICIOUS?    │                          │
│         │ MALWARE?       │                          │
│         └────────────────┘                          │
└─────────────────────────────────────────────────────┘
```

### 4 - Luồng hoạt động

#### 4.1 Chế độ Phân tích File (File Analysis Mode)

```
┌─────────────────────────────────────────────────────────────────┐
│                    FILE ANALYSIS FLOW                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  [INPUT: file.exe]                                              │
│     │                                                           │
│     ▼                                                           │
│  ┌─────────────────────┐                                        │
│  │  1. Đọc file vào    │                                        │
│  │     memory buffer   │                                        │
│  └──────────┬──────────┘                                        │
│             │                                                   │
│             ▼                                                   │
│  ┌─────────────────────┐     ┌────────────────────────────────┐ │
│  │  2. AnalyzeAPIs()   │────▶│ Quét chuỗi NT API trong file   │ │
│  │                     │     │ • Critical APIs: +15 → +35 pts │ │
│  │                     │     │ • Supporting APIs              │ │
│  │                     │     │ • Suspicious APIs              │ │
│  └──────────┬──────────┘     └────────────────────────────────┘ │
│             │                                                   │
│             ▼                                                   │
│  ┌─────────────────────┐     ┌────────────────────────────────┐ │
│  │  3. AnalyzeEntropy()│────▶│ Tính Shannon Entropy           │ │
│  │                     │     │ • H > 7.8: +30 pts (Very High) │ │
│  │                     │     │ • H > 7.5: +20 pts (High)      │ │
│  └──────────┬──────────┘     └────────────────────────────────┘ │
│             │                                                   │
│             ▼                                                   │
│  ┌─────────────────────┐     ┌────────────────────────────────┐ │
│  │  4. AnalyzeSignature│────▶│ WinVerifyTrust API             │ │
│  │     ()              │     │ • Microsoft signed: 0 pts      │ │
│  │                     │     │ • Third-party: +20 pts         │ │
│  │                     │     │ • Not signed: +25 pts          │ │
│  │                     │     │ • Invalid: +40 pts             │ │
│  └──────────┬──────────┘     └────────────────────────────────┘ │
│             │                                                   │
│             ▼                                                   │
│  ┌─────────────────────┐                                        │
│  │  5. GenerateVerdict │                                        │
│  │     ()              │                                        │
│  └──────────┬──────────┘                                        │
│             │                                                   │
│             ▼                                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  [OUTPUT]                                               │    │
│  │  • Total Score                                          │    │
│  │  • List of Indicators                                   │    │
│  │  • Verdict: CLEAN / SUSPICIOUS / MALWARE                │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

**Command:** `Phantom_Hunter.exe <file.exe>`

---

#### 4.2 Chế độ Quét Nhanh (Quick Scan / Snapshot Mode)

```
┌─────────────────────────────────────────────────────────────────┐
│                    QUICK SCAN FLOW                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────┐                                    │
│  │ 1. CreateToolhelp32     │                                    │
│  │    Snapshot()           │                                    │
│  │    (TH32CS_SNAPPROCESS) │                                    │
│  └───────────┬─────────────┘                                    │
│              │                                                  │
│              ▼                                                  │
│  ┌─────────────────────────┐                                    │
│  │ 2. Process32First/Next  │◀─────────────────────┐             │
│  │    Loop qua tất cả      │                      │             │
│  │    processes            │                      │             │
│  └───────────┬─────────────┘                      │             │
│              │                                    │             │
│              ▼                                    │             │
│  ┌─────────────────────────────────────────┐     │             │
│  │ 3. Với mỗi Process:                     │     │             │
│  │                                         │     │             │
│  │  ┌───────────────────────────────────┐  │     │             │
│  │  │ a) CheckThreadHijacking()         │  │     │             │
│  │  │    • GetThreadContext(RIP/EIP)    │  │     │             │
│  │  │    • VirtualQueryEx(mbi.Type)     │  │     │             │
│  │  │    • RIP→MEM_PRIVATE? +60 pts ⚠️  │  │     │             │
│  │  └───────────────────────────────────┘  │     │             │
│  │                 │                       │     │             │
│  │                 ▼                       │     │             │
│  │  ┌───────────────────────────────────┐  │     │             │
│  │  │ b) CheckSuspendedThreads()        │  │     │             │
│  │  │    • Tính thời gian suspended     │  │     │             │
│  │  │    • >5s: +20 pts | >10s: +35 pts │  │     │             │
│  │  └───────────────────────────────────┘  │     │             │
│  │                 │                       │     │             │
│  │                 ▼                       │     │             │
│  │  ┌───────────────────────────────────┐  │     │             │
│  │  │ c) ScanProcessMemory()            │  │     │             │
│  │  │    • Quét MEM_PRIVATE + EXECUTE   │  │     │             │
│  │  │    • Tìm Metasploit/CS signatures │  │     │             │
│  │  │    • Payload found? +50 pts       │  │     │             │
│  │  └───────────────────────────────────┘  │     │             │
│  │                 │                       │     │             │
│  │                 ▼                       │     │             │
│  │  ┌───────────────────────────────────┐  │     │             │
│  │  │ d) CheckNetworkAnomaly()          │  │     │             │
│  │  │    • GetExtendedTcpTable()        │  │     │             │
│  │  │    • notepad.exe có network? +15  │  │     │             │
│  │  └───────────────────────────────────┘  │     │             │
│  │                 │                       │     │             │
│  └─────────────────┼───────────────────────┘     │             │
│                    │                             │             │
│                    ▼                             │             │
│         ┌────────────────────┐                   │             │
│         │ Aggregate Results  │───────────────────┘             │
│         │ (next process)     │                                 │
│         └─────────┬──────────┘                                 │
│                   │ (all done)                                 │
│                   ▼                                            │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  [OUTPUT]                                               │   │
│  │  • Total processes scanned                              │   │
│  │  • Suspicious/Malicious count                           │   │
│  │  • Flagged process list (PID + Name)                    │   │
│  │  • Verdict: CLEAN / SUSPICIOUS / MALWARE                │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

**Command:** `Phantom_Hunter.exe --scan`

---

#### 4.3 Chế độ Giám sát Liên tục (Continuous Monitor Mode)

```
┌─────────────────────────────────────────────────────────────────┐
│                 CONTINUOUS MONITOR FLOW                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────┐                                    │
│  │ 1. UpdateProcessList()  │                                    │
│  │    Lấy BASELINE         │                                    │
│  │    (snapshot ban đầu)   │                                    │
│  └───────────┬─────────────┘                                    │
│              │                                                  │
│              ▼                                                  │
│  ╔═════════════════════════════════════════════════════════╗    │
│  ║           MONITOR LOOP (mỗi 1 giây)                     ║    │
│  ╠═════════════════════════════════════════════════════════╣    │
│  ║                                                         ║    │
│  ║  ┌─────────────────────┐                                ║    │
│  ║  │ 2. UpdateProcessList│                                ║    │
│  ║  │    (snapshot mới)   │                                ║    │
│  ║  └──────────┬──────────┘                                ║    │
│  ║             │                                           ║    │
│  ║             ▼                                           ║    │
│  ║  ┌─────────────────────┐      ┌─────────────────────┐   ║    │
│  ║  │ 3. Compare với      │──YES▶│ 4. OnNewProcess()   │   ║    │
│  ║  │    previous list    │      │    ┌─────────────┐  │   ║    │
│  ║  │    New process?     │      │    │ Full Scan:  │  │   ║    │
│  ║  └──────────┬──────────┘      │    │ • Thread    │  │   ║    │
│  ║             │                 │    │   Hijacking │  │   ║    │
│  ║             │ NO              │    │ • Suspended │  │   ║    │
│  ║             │                 │    │ • Memory    │  │   ║    │
│  ║             ▼                 │    │ • Network   │  │   ║    │
│  ║  ┌─────────────────────┐      │    └──────┬──────┘  │   ║    │
│  ║  │ 5. Process          │      │           │         │   ║    │
│  ║  │    terminated?      │      │           ▼         │   ║    │
│  ║  └──────────┬──────────┘      │    ┌─────────────┐  │   ║    │
│  ║             │                 │    │ Real-time   │  │   ║    │
│  ║             │ YES             │    │ ALERT!      │  │   ║    │
│  ║             ▼                 │    └─────────────┘  │   ║    │
│  ║  ┌─────────────────────┐      └─────────────────────┘   ║    │
│  ║  │ 6. OnProcessTermi-  │                                ║    │
│  ║  │    nated()          │                                ║    │
│  ║  │    (Log nếu tên     │                                ║    │
│  ║  │     đáng ngờ)       │                                ║    │
│  ║  └──────────┬──────────┘                                ║    │
│  ║             │                                           ║    │
│  ║             ▼                                           ║    │
│  ║  ┌─────────────────────┐                                ║    │
│  ║  │ Sleep(1 second)     │                                ║    │
│  ║  └──────────┬──────────┘                                ║    │
│  ║             │                                           ║    │
│  ║             └────────────────────────────────▶ LOOP     ║    │
│  ╚═════════════════════════════════════════════════════════╝    │
│                        │                                        │
│                        │ Ctrl+C                                 │
│                        ▼                                        │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  [STOP]                                                 │    │
│  │  • Total scans performed                                │    │
│  │  • Summary of detected threats                          │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

**Command:** `Phantom_Hunter.exe --monitor`

---

#### 4.4 Luồng phát hiện Thread Context Hijacking (Chi tiết)

```
┌─────────────────────────────────────────────────────────────────┐
│           THREAD HIJACKING DETECTION DETAIL                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ 1. OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFO)   │    │
│  └───────────────────────────┬─────────────────────────────┘    │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ 2. GetThreadContext(&ctx)                               │    │
│  │    ctx.ContextFlags = CONTEXT_FULL                      │    │
│  └───────────────────────────┬─────────────────────────────┘    │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ 3. Lấy Instruction Pointer                              │    │
│  │    #ifdef _WIN64                                        │    │
│  │        ip = ctx.Rip;    // 64-bit                       │    │
│  │    #else                                                │    │
│  │        ip = ctx.Eip;    // 32-bit                       │    │
│  │    #endif                                               │    │
│  └───────────────────────────┬─────────────────────────────┘    │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ 4. VirtualQueryEx(hProcess, (LPCVOID)ip, &mbi)          │    │
│  │    Kiểm tra vùng nhớ mà IP đang trỏ tới                 │    │
│  └───────────────────────────┬─────────────────────────────┘    │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ 5. KIỂM TRA ĐIỀU KIỆN CRITICAL:                         │    │
│  │                                                         │    │
│  │    if (mbi.Type == MEM_PRIVATE &&                       │    │
│  │        (mbi.Protect == PAGE_EXECUTE_READ ||             │    │
│  │         mbi.Protect == PAGE_EXECUTE_READWRITE))         │    │
│  │                                                         │    │
│  │    ┌─────────────────────────────────────────────────┐  │    │
│  │    │ Normal Process:                                 │  │    │
│  │    │   mbi.Type = MEM_IMAGE (từ PE file)            │  │    │
│  │    │   → CLEAN ✅                                   │  │    │
│  │    ├─────────────────────────────────────────────────┤  │    │
│  │    │ Injected Process:                               │  │    │
│  │    │   mbi.Type = MEM_PRIVATE (allocate thủ công)   │  │    │
│  │    │   → HIJACKING DETECTED! ⚠️ +60 points          │  │    │
│  │    └─────────────────────────────────────────────────┘  │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Giải thích Memory Type:**

| Memory Type   | Ý nghĩa                                              | Verdict                               |
| ------------- | ---------------------------------------------------- | ------------------------------------- |
| `MEM_IMAGE`   | Code được map từ PE file (.exe, .dll)                | ✅ Legitimate                         |
| `MEM_PRIVATE` | Memory được allocate bằng VirtualAlloc/NtAllocate... | ⚠️ **SUSPICIOUS** - Có thể shellcode! |
| `MEM_MAPPED`  | Memory-mapped file                                   | Cần kiểm tra thêm                     |

---

#### 4.5 Luồng xử lý Whitelist

```
┌─────────────────────────────────────────────────────────────────┐
│                    WHITELIST PROCESSING                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ Process Name: "svchost.exe"                             │    │
│  └───────────────────────────┬─────────────────────────────┘    │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ IsWhitelistedProcess()?                                 │    │
│  │                                                         │    │
│  │ WHITELIST = [                                           │    │
│  │   "explorer.exe", "svchost.exe", "csrss.exe",          │    │
│  │   "services.exe", "lsass.exe", "winlogon.exe",         │    │
│  │   "System", "smss.exe", "wininit.exe"                  │    │
│  │ ]                                                       │    │
│  └───────────────────────────┬─────────────────────────────┘    │
│                              │                                  │
│              ┌───────────────┴───────────────┐                  │
│              │                               │                  │
│              ▼ YES (Whitelisted)             ▼ NO               │
│  ┌───────────────────────┐       ┌───────────────────────┐      │
│  │ CHỈ kiểm tra:         │       │ FULL ANALYSIS:        │      │
│  │                       │       │                       │      │
│  │ ✅ Thread Hijacking   │       │ ✅ Thread Hijacking   │      │
│  │    (vì có thể là      │       │ ✅ Suspended Threads  │      │
│  │     VICTIM của        │       │ ✅ Memory Scan        │      │
│  │     injection!)       │       │ ✅ Network Anomaly    │      │
│  │                       │       │                       │      │
│  │ ❌ Skip các check     │       │                       │      │
│  │    khác (giảm FP)     │       │                       │      │
│  └───────────────────────┘       └───────────────────────┘      │
│                                                                 │
│  Lý do: System processes như svchost.exe có thể:               │
│  • Có nhiều suspended threads (normal behavior)                 │
│  • Có network connections (normal behavior)                     │
│  • NHƯNG nếu bị inject → Thread Hijacking vẫn phát hiện được!  │
└─────────────────────────────────────────────────────────────────┘
```

### 5 - Cách xây dựng

Để đảm bảo Phantom Hunter hoạt động hiệu quả và tương thích với Malware (được viết bằng C/C++), quy trình xây dựng như sau:

#### 5.1 Yêu cầu hệ thống

| Thành phần       | Yêu cầu                             |
| ---------------- | ----------------------------------- |
| **OS**           | Windows 10/11 (x64)                 |
| **IDE**          | Visual Studio 2022                  |
| **Compiler**     | MSVC v143+                          |
| **Windows SDK**  | 10.0.19041.0 hoặc mới hơn           |
| **Architecture** | x64 (bắt buộc để đọc thanh ghi RIP) |

#### 5.2 Cấu hình Project

**Project Settings trong Visual Studio:**

```
Configuration: Release
Platform: x64

C/C++ Settings:
├── General
│   └── Warning Level: Level4 (/W4)
├── Optimization
│   └── Optimization: Maximum Optimization (/O2)
├── Preprocessor
│   └── Preprocessor Definitions: WIN32;NDEBUG;_CONSOLE
├── Code Generation
│   └── Runtime Library: Multi-threaded (/MT) ← QUAN TRỌNG!
│   └── Security Check: Enable (/GS)
└── Language
    └── C++ Language Standard: ISO C++17 (/std:c++17)

Linker Settings:
├── General
│   └── Enable Incremental Linking: No
├── Input
│   └── Additional Dependencies:
│       psapi.lib
│       advapi32.lib
│       wintrust.lib
│       crypt32.lib
│       iphlpapi.lib
│       ws2_32.lib
└── Optimization
    └── References: Yes (/OPT:REF)
    └── COMDAT Folding: Yes (/OPT:ICF)
```

**Tại sao Runtime Library phải là /MT (Multi-threaded Static)?**

```
┌─────────────────────────────────────────────────────────────────┐
│                    RUNTIME LIBRARY OPTIONS                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  /MD (Multi-threaded DLL):                                      │
│  ├── Depends on: VCRUNTIME140.dll, MSVCP140.dll                │
│  ├── File size: ~150KB                                          │
│  └── ❌ Cần cài Visual C++ Redistributable                     │
│                                                                 │
│  /MT (Multi-threaded Static): ← CHỌN CÁI NÀY                   │
│  ├── Depends on: Nothing (standalone)                           │
│  ├── File size: ~500KB                                          │
│  └── ✅ Chạy độc lập, không cần cài thêm gì                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### 5.3 Cấu trúc Source Code

```
phantom-hunter/
├── phantom_hunter_detector.cpp    # Main source file
├── phantom_hunter_config.h        # Configuration & constants
├── Phantom_Hunter.sln            # Visual Studio Solution
├── Phantom_Hunter.vcxproj        # Project file
├── README.md                     # Documentation
└── x64/
    └── Release/
        └── Phantom_Hunter.exe    # Output binary
```

#### 5.4 Build Steps

```batch
# Option 1: Visual Studio GUI
1. Mở Phantom_Hunter.sln
2. Chọn Configuration: Release, Platform: x64
3. Build → Build Solution (Ctrl+Shift+B)

# Option 2: Command Line (Developer Command Prompt)
cd path\to\phantom-hunter
msbuild Phantom_Hunter.sln /p:Configuration=Release /p:Platform=x64

# Option 3: Direct cl.exe
cl.exe /EHsc /O2 /MT /std:c++17 ^
    phantom_hunter_detector.cpp ^
    /link psapi.lib advapi32.lib wintrust.lib crypt32.lib iphlpapi.lib ws2_32.lib ^
    /out:Phantom_Hunter.exe
```

#### 5.5 Kiểm tra Build thành công

```batch
# Verify binary
> Phantom_Hunter.exe --help

=========================================
============= Phantom Hunter ============
=========================================
MODES:
  Phantom_Hunter.exe <file>         - Analyze specific file (static)
  Phantom_Hunter.exe --scan         - Quick system scan (snapshot)
  Phantom_Hunter.exe --monitor      - Continuous monitoring (real-time)
  Phantom_Hunter.exe --help         - Show this help
```

### 6 - Hướng dẫn sử dụng

#### 6.1 Chế độ Phân tích File

Phân tích tĩnh một file PE để tìm dấu hiệu injection:

```batch
# Phân tích file cụ thể
> Phantom_Hunter.exe C:\suspect\malware.exe

# Output example:
[+] ========== STATIC ANALYSIS ==========
[*] Analyzing file: C:\suspect\malware.exe
[!] Critical NT API: NtAllocateVirtualMemory (x1)
[!] Critical NT API: NtWriteVirtualMemory (x1)
[!] Critical NT API: NtSetContextThread (x1)
[*] File entropy: 5.87 / 8.0
[!] File not digitally signed

[+] =========== DETECTION RESULT ===========
Target: C:\suspect\malware.exe
Score: 60.0
Indicators:
  - Critical NT API: NtAllocateVirtualMemory
  - Critical NT API: NtSetContextThread
  - Multiple critical NT APIs (3+)
  - Not signed

Verdict: [!] SUSPICIOUS
Recommendation: INVESTIGATE
```

#### 6.2 Chế độ Quét Nhanh

Chụp snapshot và phân tích tất cả process đang chạy:

```batch
# Chạy với quyền Administrator!
> Phantom_Hunter.exe --scan

# Output example:
[+] ========== DYNAMIC ANALYSIS ==========
[*] Scanning active processes...

[Detect] ========================================
[Detect] Thread Context Hijacking detected!!!
[Detect] Process: conhost.exe (PID: 12456)
[Detect] RIP: 0x000001A2B3C4D000 → MEM_PRIVATE
[Detect] ========================================

[*] Scanned 156 processes
[Detect] Found 1 MALICIOUS process(es)!

[!] Flagged Processes:
  - PID 12456: conhost.exe

[+] =========== DETECTION RESULT ===========
Target: [SYSTEM SCAN]
Score: 60.0
Indicators:
  - conhost.exe: THREAD CONTEXT HIJACKING DETECTED!!!

Verdict: [!] SUSPICIOUS
Recommendation: INVESTIGATE
Affected PID: 12456
```

#### 6.3 Chế độ Giám sát Liên tục

Theo dõi real-time các process mới được tạo:

```batch
# Chạy với quyền Administrator!
> Phantom_Hunter.exe --monitor

# Output example:
[+] ========== CONTINUOUS MONITORING MODE ==========
[*] Real-time process monitoring started
[*] Poll interval: 1 second
[*] Press Ctrl+C to stop

[*] Baseline: 158 processes

[!] NEW PROCESS DETECTED
    Name: suspicious.exe
    PID: 15678
    Time: 14:32:15

    --- Analysis Result ---
    Score: 110.0
    Indicators:
      - THREAD CONTEXT HIJACKING DETECTED!!!
      - Metasploit signature detected in memory
    Verdict: [SUSPICIOUS] - INVESTIGATE

[*] Monitoring... (Scans: 60, Processes: 159)

^C
[*] Stopping monitor...
[+] Monitor stopped (Total scans: 127)
```

#### 6.4 Quyền Administrator

⚠️ **QUAN TRỌNG**: Phantom Hunter cần quyền Administrator để:

1. **Đọc memory của process khác** (`ReadProcessMemory`)
2. **Lấy thread context** (`GetThreadContext`)
3. **Query memory information** (`VirtualQueryEx`)
4. **Truy cập system processes** (`OpenProcess`)

```batch
# Cách chạy với quyền Admin:
# 1. Right-click Command Prompt → "Run as administrator"
# 2. Hoặc:
runas /user:Administrator "Phantom_Hunter.exe --scan"
```

### 7 - Kết quả Demo

#### 7.1 Trước khi chạy Phantom Hollowing

```batch
> Phantom_Hunter.exe --scan

[+] ========== DYNAMIC ANALYSIS ==========
[*] Scanning active processes...
[*] Scanned 156 processes

[+] =========== DETECTION RESULT ===========
Target: [SYSTEM SCAN]
Score: 0.0
Indicators:
  - No suspicious indicators

Verdict: [+] CLEAN
Recommendation: No action needed
```

#### 7.2 Sau khi chạy Phantom Hollowing (Injection detected!)

```batch
> Phantom_Hunter.exe --scan

[+] ========== DYNAMIC ANALYSIS ==========
[*] Scanning active processes...

[Detect] ========================================
[Detect] Thread Context Hijacking detected!!!
[Detect] Process: conhost.exe (PID: 23456)
[Detect] RIP: 0x000001ABCD123000 → MEM_PRIVATE
[Detect] ========================================

[!] Process conhost.exe (PID: 23456) has network connections!
[*] Scanned 157 processes
[Detect] Found 1 MALICIOUS process(es)!

[!] Flagged Processes:
  - PID 23456: conhost.exe

[+] =========== DETECTION RESULT ===========
Target: [SYSTEM SCAN]
Score: 75.0
Indicators:
  - conhost.exe: THREAD CONTEXT HIJACKING DETECTED!!! (IP --> MEM_PRIVATE)
  - conhost.exe: Network-unsafe process has active connections

Verdict: [!] SUSPICIOUS
Recommendation: INVESTIGATE

Affected PID: 23456
```

### 8 - Hạn chế và Hướng phát triển

#### 8.1 Hạn chế hiện tại

| Hạn chế                   | Mô tả                                                    | Mức độ ảnh hưởng    |
| ------------------------- | -------------------------------------------------------- | ------------------- |
| **JIT False Positive**    | .NET/Java processes có thể trigger MEM_PRIVATE detection | Thấp (có whitelist) |
| **Polling-based Monitor** | Có thể miss process tồn tại <1 giây                      | Trung bình          |
| **Single-machine**        | Chưa hỗ trợ remote scanning                              | Thấp                |
| **Limited Signatures**    | Chỉ có Metasploit/Cobalt Strike signatures               | Trung bình          |

#### 8.2 Hướng phát triển

1. **Kernel Driver** - Hook `NtCreateProcess`/`NtResumeThread` để detect realtime
2. **YARA Integration** - Thêm YARA rules cho signature matching
3. **Machine Learning** - Train model để detect unknown payloads
4. **Network Integration** - Gửi alert đến SIEM/SOC
5. **Memory Forensics** - Export memory dumps cho deep analysis
6. **Multi-platform** - Port sang Linux (ptrace-based detection)
