/*
============================================================
============================================================
                   PHANTOM HUNTER - DETECTOR
    Detectior for Phantom Hollowing, Thread Context
            Hijacking & Process Hollowing
============================================================
============================================================
    Author: cyb3rhurr1c4n3
    Warning: For research and educational purpose only
============================================================
============================================================
*/



// ========== LIBRARY DECLARATION ==========
// IMPORTANT: winsock2.h MUST be included BEFORE windows.h to avoid redefinition errors
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <wintrust.h>
#include <softpub.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <map>
#include <set>
#include <vector>
#include <string>
#include <memory>
#include <thread>
#include <atomic>
#include <chrono>
#include <algorithm>
#include "phantom_hunter_config.h"

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")



// ========== LOGGING MACROS ==========
#define LOG_SUCCESS(msg, ...) printf("\n[+] " msg "\n", ##__VA_ARGS__)
#define LOG_ERROR(msg, ...)   printf("\n[-] " msg "\n", ##__VA_ARGS__)
#define LOG_INFO(msg, ...)    printf("\n[*] " msg "\n", ##__VA_ARGS__)
#define LOG_WARN(msg, ...)    printf("\n[!] " msg "\n", ##__VA_ARGS__)
#define LOG_DETECT(msg, ...)  printf("\n[Detect] " msg "\n", ##__VA_ARGS__)



// ========== DETECTION RESULT STRUCTURE ==========
struct DetectionResult {
    double suspicionScore;
    int pid;
    std::string filePath;
    std::vector<std::string> indicators;
    std::string verdict;

    DetectionResult() : suspicionScore(0.0), pid(-1), verdict("UNKNOWN") {}

    void AddIndicator(const std::string& indicator) {
        indicators.push_back(indicator);
    }

    void AddScore(double score, const std::string& reason = "") {
        suspicionScore += score;
        if (!reason.empty()) {
            AddIndicator(reason);
        }
    }

    bool IsMalicious() const { return suspicionScore >= Config::Threshold::MALWARE; }
    bool IsSuspicious() const { return suspicionScore >= Config::Threshold::SUSPICIOUS; }
    bool IsClean() const { return suspicionScore < Config::Threshold::SUSPICIOUS; }
};



// ========== FOWARD DECLARATIONS ==========
class EntropyCalculator;
class SignatureVerifier;
class ThreadAnalyzer;
class FileAnalyzer;
class ProcessMonitor;
class ContinuousMonitor;



// ========== ULTILITIES FUNCTION ==========
// Utility function to convert WCHAR (wide string) to std::string (ANSI)
static std::string WideToAnsi(const WCHAR* wstr)
{
    if (!wstr) return std::string();
    int len = WideCharToMultiByte(CP_ACP, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1) return std::string();
    std::string str(len - 1, '\0');
    WideCharToMultiByte(CP_ACP, 0, wstr, -1, &str[0], len, nullptr, nullptr);
    return str;
}



// ========== ENTROPY CALCULATOR CLASS ==========
class EntropyCalculator {
public:
    static double Calculate(const unsigned char* buffer, size_t size) {
        if (!buffer || size == 0) return 0.0;

        int frequencies[256] = { 0 };
        for (size_t i = 0; i < size; i++) {
            frequencies[buffer[i]]++;
        }

        double entropy = 0.0;
        for (int i = 0; i < 256; i++) {
            if (frequencies[i] > 0) {
                double probability = (double)frequencies[i] / size;
                entropy -= probability * log2(probability);
            }
        }

        return entropy;
    }
};



// ========== SIGNATURE VERIFIER CLASS ==========
class SignatureVerifier {
public:
    enum Status {
        VALID_MICROSOFT,
        VALID_OTHER,
        INVALID,
        NOT_SIGNED,
        ERROR_SIG
    };

    static Status VerifyFile(const char* filePath) {
        wchar_t wFilePath[MAX_PATH];
        if (MultiByteToWideChar(CP_ACP, 0, filePath, -1, wFilePath, MAX_PATH) == 0) {
            return ERROR_SIG;
        }
        return VerifyEmbeddedSignature(wFilePath);
    }

private:
    static Status VerifyEmbeddedSignature(const wchar_t* filePath) {
        WINTRUST_FILE_INFO fileInfo = { 0 };
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = filePath;

        WINTRUST_DATA winTrustData = { 0 };
        winTrustData.cbStruct = sizeof(winTrustData);
        winTrustData.dwUIChoice = WTD_UI_NONE;
        winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
        winTrustData.dwProvFlags = WTD_SAFER_FLAG;
        winTrustData.pFile = &fileInfo;

        GUID actionID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG status = WinVerifyTrust(NULL, &actionID, &winTrustData);

        winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &actionID, &winTrustData);

        if (status != ERROR_SUCCESS) {
            if (status == TRUST_E_NOSIGNATURE) return NOT_SIGNED;
            if (status == TRUST_E_BAD_DIGEST || status == TRUST_E_EXPLICIT_DISTRUST) return INVALID;
            return ERROR_SIG;
        }

        return CheckMicrosoftSigner(filePath);
    }

    static Status CheckMicrosoftSigner(const wchar_t* filePath) {
        HCERTSTORE hStore = NULL;
        HCRYPTMSG hMsg = NULL;
        DWORD dwEncoding, dwContentType, dwFormatType;
        PCMSG_SIGNER_INFO pSignerInfo = NULL;
        DWORD dwSignerInfo;
        PCCERT_CONTEXT pCertContext = NULL;
        bool isMicrosoft = false;

        if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
            0, &dwEncoding, &dwContentType, &dwFormatType, &hStore, &hMsg, NULL)) {
            goto cleanup;
        }

        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo)) {
            goto cleanup;
        }

        pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
        if (!pSignerInfo || !CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &dwSignerInfo)) {
            goto cleanup;
        }

        CERT_INFO certInfo;
        certInfo.Issuer = pSignerInfo->Issuer;
        certInfo.SerialNumber = pSignerInfo->SerialNumber;

        pCertContext = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0, CERT_FIND_SUBJECT_CERT, (PVOID)&certInfo, NULL);

        if (pCertContext) {
            DWORD dwData = CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
            if (dwData > 0) {
                wchar_t* szName = new wchar_t[dwData];
                CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, szName, dwData);
                if (wcsstr(szName, L"Microsoft") || wcsstr(szName, L"MICROSOFT")) {
                    isMicrosoft = true;
                }
                delete[] szName;
            }
        }

    cleanup:
        if (pCertContext) CertFreeCertificateContext(pCertContext);
        if (pSignerInfo) LocalFree(pSignerInfo);
        if (hStore) CertCloseStore(hStore, 0);
        if (hMsg) CryptMsgClose(hMsg);

        return isMicrosoft ? VALID_MICROSOFT : VALID_OTHER;
    }
};



// ========== THREAD ANALYZER CLASS ==========
class ThreadAnalyzer {
public:
    bool CheckThreadHijacking(HANDLE hProcess, DWORD pid, const char* procName, DetectionResult& result) {
        HANDLE snapThread = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapThread == INVALID_HANDLE_VALUE) return false;

        bool detected = false;
        THREADENTRY32 te = { 0 };
        te.dwSize = sizeof(THREADENTRY32);

        if (Thread32First(snapThread, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    if (AnalyzeThread(hProcess, te.th32ThreadID, pid, procName, result)) {
                        detected = true;
                    }
                }
            } while (Thread32Next(snapThread, &te));
        }

        CloseHandle(snapThread);
        return detected;
    }

    void CheckSuspendedThreads(HANDLE hProcess, DWORD pid, const char* procName, DWORD processCreateTime, DetectionResult& result) {
        HANDLE snapThread = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapThread == INVALID_HANDLE_VALUE) return;

        THREADENTRY32 te = { 0 };
        te.dwSize = sizeof(THREADENTRY32);
        int suspendedCount = 0;
        DWORD currentTime = GetTickCount();

        if (Thread32First(snapThread, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                    if (hThread) {
                        DWORD suspendCount = SuspendThread(hThread);
                        if (suspendCount > 0) {
                            suspendedCount++;
                            // Tính thời gian suspended
                            DWORD suspendDuration = currentTime - processCreateTime;
                            
                            if (suspendDuration > Config::Score::DynamicAnalysis::SUSPENSION_TIME_CRITICAL) {
                                LOG_WARN("Process %s (PID: %d) suspended for >%lu ms (CRITICAL)", 
                                         procName, pid, suspendDuration);
                                result.AddScore(Config::Score::DynamicAnalysis::SUSPENDED_PROCESS_LONG, 
                                               "Process suspended for extended time (>10s)");
                                result.pid = pid;
                            }
                            else if (suspendDuration > Config::Score::DynamicAnalysis::SUSPENSION_TIME_WARNING) {
                                LOG_WARN("Process %s (PID: %d) suspended for >%lu ms", 
                                         procName, pid, suspendDuration);
                                result.AddScore(Config::Score::DynamicAnalysis::SUSPENDED_PROCESS, 
                                               "Process suspended for moderate time (>5s)");
                                result.pid = pid;
                            }
                        }
                        ResumeThread(hThread);
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(snapThread, &te));
        }

        if (suspendedCount > 0) {
            LOG_INFO("Process %s (PID: %d) has %d suspended thread(s)", procName, pid, suspendedCount);
        }

        CloseHandle(snapThread);
    }

private:
    bool AnalyzeThread(HANDLE hProcess, DWORD threadId, DWORD pid, const char* procName, DetectionResult& result) {
        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, threadId);
        if (!hThread) return false;

        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_FULL;
        bool hijacked = false;

        if (GetThreadContext(hThread, &ctx)) {
#ifdef _WIN64
            DWORD_PTR ip = ctx.Rip;
#else
            DWORD_PTR ip = ctx.Eip;
#endif
            MEMORY_BASIC_INFORMATION mbi = { 0 };
            if (VirtualQueryEx(hProcess, (LPCVOID)ip, &mbi, sizeof(mbi))) {
                if ((mbi.Type == MEM_PRIVATE) &&
                    (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE)) {

                    LOG_DETECT("========================================");
                    LOG_DETECT("Thread Context Hijacking detected!!!");
                    LOG_DETECT("Process: %s (PID: %d)", procName, pid);
#ifdef _WIN64
                    LOG_DETECT("RIP: 0x%016llx → MEM_PRIVATE", ip);
#else
                    LOG_DETECT("EIP: 0x%08x → MEM_PRIVATE", ip);
#endif
                    LOG_DETECT("========================================");

                    result.AddScore(Config::Score::DynamicAnalysis::THREAD_HIJACKING,
                        "THREAD CONTEXT HIJACKING DETECTED!!! (IP --> MEM_PRIVATE)");
                    result.pid = pid;
                    hijacked = true;
                }
            }
        }

        CloseHandle(hThread);
        return hijacked;
    }
};



// ========== MEMORY SCANNER CLASS ==========
class MemoryScanner {
public:
    void ScanProcessMemory(HANDLE hProcess, DWORD pid, const char* procName, DetectionResult& result) {
        if (!Config::ENABLE_MEMORY_SCAN) return;

        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        
        LPVOID addr = sysInfo.lpMinimumApplicationAddress;
        LPVOID maxAddr = sysInfo.lpMaximumApplicationAddress;
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        size_t totalScanned = 0;

        while (addr < maxAddr && totalScanned < Config::Performance::MAX_MEMORY_SCAN_PER_PROCESS) {
            if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
                // Scan MEM_PRIVATE regions with EXECUTE permission
                if (mbi.Type == MEM_PRIVATE && 
                    (mbi.Protect & PAGE_EXECUTE_READ || mbi.Protect & PAGE_EXECUTE_READWRITE) &&
                    mbi.State == MEM_COMMIT) {
                    
                    size_t regionSize = mbi.RegionSize;
                    if (regionSize > 0 && regionSize < 10 * 1024 * 1024) { // Max 10MB per region
                        auto buffer = std::make_unique<unsigned char[]>(regionSize);
                        SIZE_T bytesRead = 0;
                        
                        if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.get(), regionSize, &bytesRead)) {
                            if (SearchPayloadSignatures(buffer.get(), bytesRead, procName, pid, result)) {
                                LOG_DETECT("Payload signature found in process %s (PID: %d)", procName, pid);
                            }
                            totalScanned += bytesRead;
                        }
                    }
                }
                addr = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
            }
            else {
                addr = (LPVOID)((DWORD_PTR)addr + 0x1000);
            }
        }
    }

private:
    bool SearchPayloadSignatures(const unsigned char* buffer, size_t size, const char* procName, DWORD pid, DetectionResult& result) {
        bool found = false;

        // Search Metasploit patterns
        for (int i = 0; i < Config::PayloadSignatures::METASPLOIT_PATTERNS_COUNT; ++i) {
            if (SearchPattern(buffer, size, Config::PayloadSignatures::METASPLOIT_PATTERNS[i])) {
                result.AddScore(Config::Score::DynamicAnalysis::PAYLOAD_SIGNATURE_DETECTED, 
                               "Metasploit signature detected in memory");
                result.pid = pid;
                found = true;
                break;
            }
        }

        // Search Cobalt Strike patterns
        for (int i = 0; i < Config::PayloadSignatures::COBALT_STRIKE_PATTERNS_COUNT; ++i) {
            if (SearchPattern(buffer, size, Config::PayloadSignatures::COBALT_STRIKE_PATTERNS[i])) {
                result.AddScore(Config::Score::DynamicAnalysis::PAYLOAD_SIGNATURE_DETECTED, 
                               "Cobalt Strike signature detected in memory");
                result.pid = pid;
                found = true;
                break;
            }
        }

        // Search C2 beacon patterns (lower score as these can be legitimate)
        int c2MatchCount = 0;
        for (int i = 0; i < Config::PayloadSignatures::C2_PATTERNS_COUNT; ++i) {
            if (SearchPattern(buffer, size, Config::PayloadSignatures::C2_PATTERNS[i])) {
                c2MatchCount++;
            }
        }
        // Only flag if multiple C2 patterns found in executable memory
        if (c2MatchCount >= 2) {
            result.AddScore(Config::Score::DynamicAnalysis::CODE_CAVE_DETECTED, 
                           "Multiple C2 patterns detected in executable memory");
            result.pid = pid;
            found = true;
        }

        return found;
    }

    bool SearchPattern(const unsigned char* buffer, size_t size, const char* pattern) const {
        size_t patternLen = strlen(pattern);
        if (patternLen > size) return false;

        for (size_t i = 0; i <= size - patternLen; i++) {
            if (memcmp(&buffer[i], pattern, patternLen) == 0) {
                return true;
            }
        }
        return false;
    }
};



// ========== NETWORK ANALYZER CLASS ==========
class NetworkAnalyzer {
public:
    void CheckNetworkAnomaly(DWORD pid, const char* procName, DetectionResult& result) {
        if (!Config::ENABLE_NETWORK_MONITORING) return;

        // Check if this is a network-unsafe process
        if (IsNetworkUnsafeProcess(procName)) {
            if (HasActiveConnections(pid)) {
                LOG_WARN("Network anomaly: %s (PID: %d) has network connections!", procName, pid);
                result.AddScore(Config::Score::DynamicAnalysis::SUSPICIOUS_NETWORK, 
                               "Network-unsafe process has active connections");
                result.pid = pid;
            }
        }
    }

private:
    bool IsNetworkUnsafeProcess(const char* procName) const {
        // Processes that should NEVER have network connections
        const char* NETWORK_UNSAFE[] = {
            "notepad.exe",
            "calc.exe",
            "mspaint.exe",
            "write.exe",
            "charmap.exe",
            "magnify.exe",
            "osk.exe",
            "wordpad.exe"
        };

        std::string lowerName = procName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

        for (const char* unsafe : NETWORK_UNSAFE) {
            if (lowerName == unsafe) {
                return true;
            }
        }
        return false;
    }

    bool HasActiveConnections(DWORD pid) const {
        // Get TCP table size
        DWORD dwSize = 0;
        GetExtendedTcpTable(NULL, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        
        if (dwSize == 0) return false;
        
        // Allocate buffer
        auto pTcpTable = std::make_unique<BYTE[]>(dwSize);
        PMIB_TCPTABLE_OWNER_PID pTable = (PMIB_TCPTABLE_OWNER_PID)pTcpTable.get();
        
        // Get TCP table
        if (GetExtendedTcpTable(pTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
            return false;
        }
        
        // Check if any connection belongs to this PID
        for (DWORD i = 0; i < pTable->dwNumEntries; i++) {
            if (pTable->table[i].dwOwningPid == pid) {
                // Found a connection for this process
                // Check if it's an active connection (not listening, not closed)
                if (pTable->table[i].dwState == MIB_TCP_STATE_ESTAB ||
                    pTable->table[i].dwState == MIB_TCP_STATE_SYN_SENT ||
                    pTable->table[i].dwState == MIB_TCP_STATE_SYN_RCVD) {
                    return true;
                }
            }
        }
        
        return false;
    }
};



// ========== FILE ANALYZER CLASS ==========
class FileAnalyzer {
public:
    bool Analyze(const char* filePath, DetectionResult& result) {
        LOG_SUCCESS("========== STATIC ANALYSIS ==========");
        LOG_INFO("Analyzing file: %s", filePath);

        FILE* file = nullptr;
        if (fopen_s(&file, filePath, "rb") != 0 || !file) {
            LOG_ERROR("Cannot open file: %s", filePath);
            return false;
        }

        fseek(file, 0, SEEK_END);
        long fileSize = ftell(file);
        fseek(file, 0, SEEK_SET);

        if (fileSize <= 0) {
            LOG_ERROR("Invalid file size");
            fclose(file);
            return false;
        }

        auto buffer = std::make_unique<unsigned char[]>(fileSize);
        size_t bytesRead = fread(buffer.get(), 1, fileSize, file);
        fclose(file);

        if (bytesRead != static_cast<size_t>(fileSize)) {
            LOG_ERROR("Failed to read complete file");
            return false;
        }

        AnalyzeAPIs(buffer.get(), fileSize, result);
        AnalyzeEntropy(buffer.get(), fileSize, result);
        AnalyzeSignature(filePath, result);

        return true;
    }

private:
    void AnalyzeAPIs(const unsigned char* buffer, size_t size, DetectionResult& result) {
        std::map<std::string, int> found;
        size_t suspiciousCount = 0;

        // Scan Critical APIs
        for (int i = 0; i < Config::NTAPIs::CRITICAL_APIS_COUNT; ++i) {
            const char* api = Config::NTAPIs::CRITICAL_APIS[i];
            int count = SearchString(buffer, size, api);
            if (count > 0) {
                found[api] = count;
                LOG_WARN("Critical NT API: %s (x%d)", api, count);
                result.AddIndicator(std::string("Critical NT API: ") + api);
            }
        }

        // Scan Supporting APIs
        for (int i = 0; i < Config::NTAPIs::SUPPORTING_APIS_COUNT; ++i) {
            const char* api = Config::NTAPIs::SUPPORTING_APIS[i];
            int count = SearchString(buffer, size, api);
            if (count > 0) {
                found[api] = count;
                LOG_WARN("Supporting NT API: %s (x%d)", api, count);
                result.AddIndicator(std::string("Supporting NT API: ") + api);
            }
        }

        // Scan Suspicious APIs
        for (int i = 0; i < Config::NTAPIs::SUSPICIOUS_APIS_COUNT; ++i) {
            const char* api = Config::NTAPIs::SUSPICIOUS_APIS[i];
            int count = SearchString(buffer, size, api);
            if (count > 0) {
                suspiciousCount++;
                LOG_INFO("Suspicious API: %s (x%d)", api, count);
                result.AddIndicator(std::string("Suspicious API: ") + api);
            }
        }

        // Count critical APIs found
        size_t crit_count = 0;
        for (int i = 0; i < Config::NTAPIs::CRITICAL_APIS_COUNT; ++i) {
            if (found.count(Config::NTAPIs::CRITICAL_APIS[i])) crit_count++;
        }

        // Count supporting APIs found
        size_t support_count = 0;
        for (int i = 0; i < Config::NTAPIs::SUPPORTING_APIS_COUNT; ++i) {
            if (found.count(Config::NTAPIs::SUPPORTING_APIS[i])) support_count++;
        }

        // Scoring based on API combinations
        if (crit_count >= 3) {
            result.AddScore(Config::Score::StaticAnalysis::MULTIPLE_CRITIAL_NTAPIS, "Multiple critical NT APIs (3+)");
        }
        else if (crit_count == 2) {
            result.AddScore(Config::Score::StaticAnalysis::MULTIPLE_CRITIAL_NTAPIS, "Multiple critical NT APIs");
        }
        else if (crit_count == 1) {
            if (support_count >= 3) {
                result.AddScore(Config::Score::StaticAnalysis::SINGLE_CRITIAL_AND_SUPPORT_APIS, "Critical + supporting APIs (3+)");
            }
            else {
                result.AddScore(Config::Score::StaticAnalysis::SINGLE_CRITIAL_NTAPI, "Single critical NT API");
            }
        }
        else if (suspiciousCount >= 2 || support_count >= 2) {
            result.AddScore(Config::Score::StaticAnalysis::MULTIPLE_SUSPICIOUS_AND_SUPPORT_APIS, "Multiple suspicious/supporting APIs");
        }
    }

    void AnalyzeEntropy(const unsigned char* buffer, size_t size, DetectionResult& result) {
        double entropy = EntropyCalculator::Calculate(buffer, size);
        LOG_INFO("File entropy: %.4f / 8.0", entropy);

        if (entropy > Config::Threshold::VERY_HIGH_ENTROPY) {
            result.AddScore(Config::Score::StaticAnalysis::VERY_HIGH_ENTROPY, "Very high entropy!");
            LOG_WARN("Very high entropy - likely packed/encrypted");
        }
        else if (entropy > Config::Threshold::HIGH_ENTROPY) {
            result.AddScore(Config::Score::StaticAnalysis::HIGH_ENTROPY, "High entropy");
            LOG_WARN("High entropy - possibly packed/encrypted");
        }
    }

    void AnalyzeSignature(const char* filePath, DetectionResult& result) {
        SignatureVerifier::Status status = SignatureVerifier::VerifyFile(filePath);

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
    }

    int SearchString(const unsigned char* buffer, size_t size, const char* str) const {
        int count = 0;
        size_t strLen = strlen(str);
        if (strLen > size) return 0;

        for (size_t i = 0; i <= size - strLen; i++) {
            if (memcmp(&buffer[i], str, strLen) == 0) count++;
        }
        return count;
    }
};



// ========== PROCESS MONITOR CLASS (Snapshot-based) ==========
class ProcessMonitor {
public:
    struct ScanSummary {
        int totalProcesses;
        int suspiciousProcesses;
        int maliciousProcesses;
        std::vector<std::pair<DWORD, std::string>> flaggedProcesses;

        ScanSummary() : totalProcesses(0), suspiciousProcesses(0), maliciousProcesses(0) {}
    };

    ScanSummary ScanAllProcesses(DetectionResult& globalResult) {
        LOG_SUCCESS("========== DYNAMIC ANALYSIS ==========");
        LOG_INFO("Scanning active processes...");

        ScanSummary summary;

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            LOG_ERROR("Failed to create snapshot");
            return summary;
        }

        PROCESSENTRY32W pe = { 0 };
        pe.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(snapshot, &pe)) {
            do {
                DetectionResult processResult;
                AnalyzeProcess(pe.th32ProcessID, processResult);
                summary.totalProcesses++;

                std::string procNameStr = WideToAnsi(pe.szExeFile);

                // Aggregate results
                if (processResult.IsMalicious()) {
                    summary.maliciousProcesses++;
                    summary.flaggedProcesses.push_back(std::make_pair(pe.th32ProcessID, procNameStr));
                    // Add to global result
                    globalResult.suspicionScore += processResult.suspicionScore;
                    for (const auto& ind : processResult.indicators) {
                        globalResult.AddIndicator(procNameStr + ": " + ind);
                    }
                }
                else if (processResult.IsSuspicious()) {
                    summary.suspiciousProcesses++;
                    summary.flaggedProcesses.push_back(std::make_pair(pe.th32ProcessID, procNameStr));
                    globalResult.suspicionScore += processResult.suspicionScore;
                    for (const auto& ind : processResult.indicators) {
                        globalResult.AddIndicator(procNameStr + ": " + ind);
                    }
                }
            } while (Process32NextW(snapshot, &pe));
        }

        CloseHandle(snapshot);
        
        LOG_INFO("Scanned %d processes", summary.totalProcesses);
        if (summary.maliciousProcesses > 0) {
            LOG_DETECT("Found %d MALICIOUS process(es)!", summary.maliciousProcesses);
        }
        if (summary.suspiciousProcesses > 0) {
            LOG_WARN("Found %d suspicious process(es)", summary.suspiciousProcesses);
        }

        return summary;
    }

private:
    bool IsWhitelistedProcess(const char* procName) const {
        std::string lowerName = procName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

        for (int i = 0; i < Config::ProcessWhitelist::WHITELIST_SIZE; ++i) {
            std::string whiteName = Config::ProcessWhitelist::SAFE_PROCESSES[i];
            std::transform(whiteName.begin(), whiteName.end(), whiteName.begin(), ::tolower);
            if (lowerName == whiteName) {
                return true;
            }
        }
        return false;
    }

    void AnalyzeProcess(DWORD pid, DetectionResult& result) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) return;

        char procName[MAX_PATH] = { 0 };
        GetModuleBaseNameA(hProcess, NULL, procName, MAX_PATH);

        // Skip whitelisted system processes for performance
        // Note: Still check thread hijacking for whitelisted processes as they can be victims
        bool isWhitelisted = IsWhitelistedProcess(procName);

        // Get process creation time
        FILETIME createTime, exitTime, kernelTime, userTime;
        DWORD processCreateTick = 0;
        if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
            // Convert FILETIME to approximate tick count
            ULARGE_INTEGER uli;
            uli.LowPart = createTime.dwLowDateTime;
            uli.HighPart = createTime.dwHighDateTime;
            // Approximate: use current tick minus a calculated offset
            FILETIME nowFt;
            GetSystemTimeAsFileTime(&nowFt);
            ULARGE_INTEGER nowUli;
            nowUli.LowPart = nowFt.dwLowDateTime;
            nowUli.HighPart = nowFt.dwHighDateTime;
            DWORD elapsedMs = (DWORD)((nowUli.QuadPart - uli.QuadPart) / 10000);
            processCreateTick = GetTickCount() - elapsedMs;
        }

        // Thread analysis - always check for hijacking (even whitelisted processes can be victims)
        ThreadAnalyzer threadAnalyzer;
        threadAnalyzer.CheckThreadHijacking(hProcess, pid, procName, result);
        
        // For non-whitelisted processes, do full analysis
        if (!isWhitelisted) {
            threadAnalyzer.CheckSuspendedThreads(hProcess, pid, procName, processCreateTick, result);

            // Memory scanning for payload signatures
            MemoryScanner memScanner;
            memScanner.ScanProcessMemory(hProcess, pid, procName, result);

            // Network anomaly detection
            NetworkAnalyzer netAnalyzer;
            netAnalyzer.CheckNetworkAnomaly(pid, procName, result);
        }

        CloseHandle(hProcess);
    }
};



// ========== CONTINUOUS MONITOR CLASS (NEW!) ==========
class ContinuousMonitor {
public:
    ContinuousMonitor() : running(false), scanCount(0) {}

    ~ContinuousMonitor() {
        Stop();
    }

    void Start() {
        LOG_SUCCESS("========== CONTINUOUS MONITORING MODE ==========");
        LOG_INFO("Real-time process monitoring started");
        LOG_INFO("Poll interval: 1 second");
        LOG_INFO("Press Ctrl+C to stop\n");

        running.store(true);
        monitorThread = std::thread(&ContinuousMonitor::MonitorLoop, this);
    }

    void Stop() {
        if (!running.load()) return;

        LOG_INFO("\nStopping monitor...");
        running.store(false);

        if (monitorThread.joinable()) {
            monitorThread.join();
        }

        LOG_SUCCESS("Monitor stopped (Total scans: %d)", scanCount);
    }

    void WaitForStop() {
        if (monitorThread.joinable()) {
            monitorThread.join();
        }
    }

private:
    std::atomic<bool> running;
    std::thread monitorThread;
    std::map<DWORD, std::string> knownProcesses;
    int scanCount;

    void MonitorLoop() {
        UpdateProcessList();
        LOG_INFO("Baseline: %zu processes\n", knownProcesses.size());

        while (running.load()) {
            scanCount++;
            auto previousProcs = knownProcesses;
            UpdateProcessList();

            // Detect new processes
            for (const auto& pair : knownProcesses) {
                if (previousProcs.find(pair.first) == previousProcs.end()) {
                    OnNewProcess(pair.first, pair.second);
                }
            }

            // Detect terminated processes
            for (const auto& pair : previousProcs) {
                if (knownProcesses.find(pair.first) == knownProcesses.end()) {
                    OnProcessTerminated(pair.first, pair.second);
                }
            }

            if (scanCount % 60 == 0) {
                printf("[*] Monitoring... (Scans: %d, Processes: %zu)\n", scanCount, knownProcesses.size());
            }

            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    void UpdateProcessList() {
        knownProcesses.clear();
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return;

        PROCESSENTRY32W pe = { 0 };
        pe.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(snapshot, &pe)) {
            do {
                knownProcesses[pe.th32ProcessID] = WideToAnsi(pe.szExeFile);
            } while (Process32NextW(snapshot, &pe));
        }

        CloseHandle(snapshot);
    }

    bool IsWhitelistedProcess(const std::string& procName) const {
        std::string lowerName = procName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

        for (int i = 0; i < Config::ProcessWhitelist::WHITELIST_SIZE; ++i) {
            std::string whiteName = Config::ProcessWhitelist::SAFE_PROCESSES[i];
            std::transform(whiteName.begin(), whiteName.end(), whiteName.begin(), ::tolower);
            if (lowerName == whiteName) {
                return true;
            }
        }
        return false;
    }

    void OnNewProcess(DWORD pid, const std::string& name) {
        // Check whitelist - still log but with reduced analysis
        bool isWhitelisted = IsWhitelistedProcess(name);
        
        printf("\n");
        if (isWhitelisted) {
            LOG_INFO("New system process: %s (PID: %d)", name.c_str(), pid);
        } else {
            LOG_WARN("NEW PROCESS DETECTED");
            printf("    Name: %s\n", name.c_str());
            printf("    PID: %d\n", pid);
            printf("    Time: %s", GetTimeString().c_str());
        }

        // Immediate comprehensive analysis
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProcess) {
            DetectionResult result;
            result.filePath = name;
            result.pid = pid;

            // Get process creation time
            FILETIME createTime, exitTime, kernelTime, userTime;
            DWORD processCreateTick = GetTickCount();
            if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
                FILETIME nowFt;
                GetSystemTimeAsFileTime(&nowFt);
                ULARGE_INTEGER uli, nowUli;
                uli.LowPart = createTime.dwLowDateTime;
                uli.HighPart = createTime.dwHighDateTime;
                nowUli.LowPart = nowFt.dwLowDateTime;
                nowUli.HighPart = nowFt.dwHighDateTime;
                DWORD elapsedMs = (DWORD)((nowUli.QuadPart - uli.QuadPart) / 10000);
                processCreateTick = GetTickCount() - elapsedMs;
            }

            // Always check thread hijacking (even whitelisted processes can be victims)
            ThreadAnalyzer threadAnalyzer;
            threadAnalyzer.CheckThreadHijacking(hProcess, pid, name.c_str(), result);
            
            // Full analysis only for non-whitelisted processes
            if (!isWhitelisted) {
                threadAnalyzer.CheckSuspendedThreads(hProcess, pid, name.c_str(), processCreateTick, result);

                MemoryScanner memScanner;
                memScanner.ScanProcessMemory(hProcess, pid, name.c_str(), result);

                NetworkAnalyzer netAnalyzer;
                netAnalyzer.CheckNetworkAnomaly(pid, name.c_str(), result);
            }

            CloseHandle(hProcess);

            // Generate verdict for this process (only if non-whitelisted or detected something)
            if (!isWhitelisted || result.suspicionScore > 0) {
                PrintProcessVerdict(result);
            }
        }
        printf("\n");
    }

    void PrintProcessVerdict(const DetectionResult& result) const {
        printf("\n    --- Analysis Result ---\n");
        printf("    Score: %.1f\n", result.suspicionScore);
        
        if (!result.indicators.empty()) {
            printf("    Indicators:\n");
            for (const auto& ind : result.indicators) {
                printf("      - %s\n", ind.c_str());
            }
        }

        printf("    Verdict: ");
        if (result.IsMalicious()) {
            printf("[MALWARE] - QUARANTINE IMMEDIATELY!\n");
        }
        else if (result.IsSuspicious()) {
            printf("[SUSPICIOUS] - INVESTIGATE\n");
        }
        else {
            printf("[CLEAN]\n");
        }
    }

    void OnProcessTerminated(DWORD pid, const std::string& name) {
        // Only log interesting terminations
        std::string lowerName = name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

        const char* keywords[] = { "phantom", "hollow", "inject", "suspicious", "malware", "exploit" };
        for (const char* keyword : keywords) {
            if (lowerName.find(keyword) != std::string::npos) {
                printf("[*] Interesting termination: %s (PID: %d)\n", name.c_str(), pid);
                break;
            }
        }
    }

    std::string GetTimeString() {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char buffer[64];
        sprintf_s(buffer, "%02d:%02d:%02d\n", st.wHour, st.wMinute, st.wSecond);
        return buffer;
    }
};



// ========== PHANTOM HUNTER DETECTOR CLASS ==========
class PhantomHunterDetector {
public:
    void AnalyzeFile(const char* filePath) {
        DetectionResult result;
        result.filePath = filePath;

        PrintBanner("FILE ANALYSIS MODE");

        FileAnalyzer fileAnalyzer;
        fileAnalyzer.Analyze(filePath, result);

        GenerateVerdict(result);
    }

    void QuickScan() {
        DetectionResult result;
        result.filePath = "[SYSTEM SCAN]";

        PrintBanner("SNAPSHOT SCAN MODE");

        ProcessMonitor monitor;
        ProcessMonitor::ScanSummary summary = monitor.ScanAllProcesses(result);

        // Print flagged processes
        if (!summary.flaggedProcesses.empty()) {
            printf("\n");
            LOG_WARN("Flagged Processes:");
            for (const auto& proc : summary.flaggedProcesses) {
                printf("  - PID %d: %s\n", proc.first, proc.second.c_str());
            }
        }

        GenerateVerdict(result);
    }

    void ContinuousMonitoring() {
        PrintBanner("CONTINUOUS MONITORING MODE");

        ContinuousMonitor monitor;
        SetConsoleCtrlHandler(ConsoleHandler, TRUE);
        g_monitor = &monitor;

        monitor.Start();
        monitor.WaitForStop();
    }

private:
    static ContinuousMonitor* g_monitor;

    static BOOL WINAPI ConsoleHandler(DWORD signal) {
        if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT) {
            if (g_monitor) {
                g_monitor->Stop();
            }
            return TRUE;
        }
        return FALSE;
    }

    void PrintBanner(const char* mode) const {
        printf("\n=========================================\n");
        printf("============= Phantom Hunter ============\n");
        printf("=========================================\n");
    }

    void GenerateVerdict(const DetectionResult& result) const {
        printf("\n");
        LOG_SUCCESS("=========== DETECTION RESULT ===========");
        printf("\nTarget: %s\n", result.filePath.c_str());
        printf("Score: %.1f\n", result.suspicionScore);

        printf("\nIndicators:\n");
        if (result.indicators.empty()) {
            printf("  - No suspicious indicators\n");
        }
        else {
            for (const auto& ind : result.indicators) {
                printf("  - %s\n", ind.c_str());
            }
        }

        printf("\nVerdict: ");
        if (result.IsMalicious()) {
            LOG_DETECT("MALWARE");
            printf("Recommendation: QUARANTINE IMMEDIATELY\n");
        }
        else if (result.IsSuspicious()) {
            LOG_WARN("SUSPICIOUS");
            printf("Recommendation: INVESTIGATE\n");
        }
        else {
            LOG_SUCCESS("CLEAN");
            printf("Recommendation: No action needed\n");
        }

        if (result.pid > 0) {
            printf("\nAffected PID: %d\n", result.pid);
        }
        printf("\n");
    }
};

ContinuousMonitor* PhantomHunterDetector::g_monitor = nullptr;



// ========== USAGE ==========
void PrintUsage(const char* prog) {
    printf("\n=========================================\n");
    printf("============= Phantom Hunter ============\n");
    printf("=========================================\n");

    printf("MODES:\n");
    printf("  %s <file>         - Analyze specific file (static)\n", prog);
    printf("  %s --scan         - Quick system scan (snapshot)\n", prog);
    printf("  %s --monitor      - Continuous monitoring (real-time)\n", prog);
    printf("  %s --help         - Show this help\n\n", prog);

    printf("EXAMPLES:\n");
    printf("  %s malware.exe\n", prog);
    printf("  %s --scan\n", prog);
    printf("  %s --monitor\n\n", prog);

    printf("MODE COMPARISON:\n");
    printf("  File Analysis:   Static analysis only (fast)\n");
    printf("  Quick Scan:      Snapshot of running processes\n");
    printf("  Monitor:         Real-time detection (recommended)\n\n");
}



// ========== MAIN ==========
int main(int argc, char* argv[]) {
    PhantomHunterDetector detector;

    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    std::string arg = argv[1];

    if (arg == "--help" || arg == "-h") {
        PrintUsage(argv[0]);
    }
    else if (arg == "--scan" || arg == "-s") {
        detector.QuickScan();
    }
    else if (arg == "--monitor" || arg == "-m") {
        detector.ContinuousMonitoring();
    }
    else {
        detector.AnalyzeFile(arg.c_str());
    }

    return 0;
}
