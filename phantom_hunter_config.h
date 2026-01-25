/*
============================================================
============================================================
            PHANTOM HUNTER - CONFIGURATION FILE
        Tuning and Customization for Detection Engine
============================================================
============================================================
*/



#ifndef PHANTOM_HUNTER_CONFIG_H
#define PHANTOM_HUNTER_CONFIG_H
#define PHANTOM_HUNTER_VERSION 1



namespace Config {
	// ========== GLOBAL ==========
    const bool ENABLE_MEMORY_SCAN = true;
    const bool ENABLE_NETWORK_MONITORING = true;
    const bool ENABLE_ENTROPY_ANALYSIS = true;

    // ========== DETECTION THRESHOLDS ==========
    namespace Threshold {
        const double SUSPICIOUS = 60.0;
        const double MALWARE = 120.0;
        const double HIGH_ENTROPY = 7.5;
        const double VERY_HIGH_ENTROPY = 7.8;
    }

	// ========== SCORING SYSTEM ==========
    namespace Score {

        // Static Analysis Scores
        namespace StaticAnalysis {
            const double MULTIPLE_SUSPICIOUS_AND_SUPPORT_APIS = 10.0;
            const double SINGLE_CRITIAL_NTAPI = 15.0;
            const double SINGLE_CRITIAL_AND_SUPPORT_APIS = 25.0; // 1 critical and 3+ supporting/suspicous
            const double MULTIPLE_CRITIAL_NTAPIS = 35.0;
            const double HIGH_ENTROPY = 20.0;
            const double VERY_HIGH_ENTROPY = 30.0;
            const double NOT_MICROSOFT_SIGNED = 20.0;
            const double NOT_SIGNED = 25.0;
            const double INVALID_SIG = 40.0;
            const double MULTIPLE_IMPORTS_FROM_NTDLL = 10.0;
        }

        // Dynamic Analysis Scores
        namespace DynamicAnalysis {
            const double SUSPENDED_PROCESS = 20.0;
            const double SUSPENDED_PROCESS_LONG = 35.0;
            const double THREAD_HIJACKING = 60.0;         // CRITICAL
            const double PAYLOAD_SIGNATURE_DETECTED = 50.0;
            const double SUSPICIOUS_NETWORK = 15.0;
            const double MEMORY_INJECTION_DETECTED = 40.0;
            const double CODE_CAVE_DETECTED = 25.0;
            const unsigned long SUSPENSION_TIME_WARNING = 5000;    // 5 seconds
            const unsigned long SUSPENSION_TIME_CRITICAL = 10000;  // 10 seconds
        }
    }


    // ========== NT API DEFINITIONS ==========
    namespace NTAPIs {
        // Core injection APIs
        static const char* CRITICAL_APIS[] = {
            "NtAllocateVirtualMemory",
            "NtWriteVirtualMemory",
            "NtGetContextThread",
            "NtSetContextThread",
            "NtResumeThread",
            "NtProtectVirtualMemory",
            "NtQueryVirtualMemory",
        };
        static const int CRITICAL_APIS_COUNT = sizeof(CRITICAL_APIS) / sizeof(CRITICAL_APIS[0]);

        // Supporting injection APIs
        static const char* SUPPORTING_APIS[] = {
            "NtCreateProcess",
            "NtCreateProcessEx",
            "NtCreateThread",
            "NtCreateThreadEx",
            "NtSuspendProcess",
            "NtSuspendThread",
            "NtQueueApcThread",
            "NtMapViewOfSection"
        };
        static const int SUPPORTING_APIS_COUNT = sizeof(SUPPORTING_APIS) / sizeof(SUPPORTING_APIS[0]);

        // APIs commonly used by malware but not specific to process injection
        static const char* SUSPICIOUS_APIS[] = {
            "CreateRemoteThread",
            "SetWindowsHookEx",
            "CreateFileA",
            "CreateFileW",
            "RegOpenKeyEx",
            "RegCreateKeyEx",
            "WinExec",
            "ShellExecute"
        };
        static const int SUSPICIOUS_APIS_COUNT = sizeof(SUSPICIOUS_APIS) / sizeof(SUSPICIOUS_APIS[0]);
    }

    // ========== PROCESS WHITELIST ==========
    // Các process được coi là an toàn (false positive reduction)
    namespace ProcessWhitelist {
        static const char* SAFE_PROCESSES[] = {
            "explorer.exe",           // Windows Explorer
            "svchost.exe",            // Windows Service Host
            "dwm.exe",                // Desktop Window Manager
            "csrss.exe",              // Client/Server Runtime Subsystem
            "lsass.exe",              // Local Security Authority
            "wininit.exe",            // Windows Initialization
            "services.exe",           // Services Control Manager
            "winlogon.exe",           // Windows Logon Process
            "spoolsv.exe",            // Printer Spooler
            "SearchIndexer.exe",      // Windows Search
            "TiWorker.exe"            // Windows Update
        };
        const int WHITELIST_SIZE = sizeof(SAFE_PROCESSES) / sizeof(SAFE_PROCESSES[0]);
    }

    // ========== KNOWN PAYLOAD SIGNATURES ==========
    namespace PayloadSignatures {
        // Metasploit meterpreter signature patterns
        static const char* METASPLOIT_PATTERNS[] = {
            "meterpreter",
            "reverse_tcp",
            "reverse_https"
        };
        static const int METASPLOIT_PATTERNS_COUNT = sizeof(METASPLOIT_PATTERNS) / sizeof(METASPLOIT_PATTERNS[0]);

        // Cobalt Strike beacon patterns
        static const char* COBALT_STRIKE_PATTERNS[] = {
            "\.beacon\.",
            "stageless"
        };
        static const int COBALT_STRIKE_PATTERNS_COUNT = sizeof(COBALT_STRIKE_PATTERNS) / sizeof(COBALT_STRIKE_PATTERNS[0]);

        // Common C2 beacon patterns
        static const char* C2_PATTERNS[] = {
            "User-Agent:",
            "Content-Type:",
            "cmd.exe",
            "powershell.exe"
        };
        static const int C2_PATTERNS_COUNT = sizeof(C2_PATTERNS) / sizeof(C2_PATTERNS[0]);
    }

    // ========== LOGGING CONFIGURATION ==========
    namespace Logging {
        const bool ENABLE_LOGGING = true;
        const char* LOG_FILE_PATH = "phantom_hunter.log";
        const bool LOG_TO_CONSOLE = true;
        const bool LOG_TO_FILE = true;

        enum LogLevel {
            DEBUG = 0,
            INFO = 1,
            WARNING = 2,
            ERROR_LEVEL = 3,
            CRITICAL = 4
        };

        const LogLevel MIN_LOG_LEVEL = INFO;
    }

    // ========== HEURISTIC SETTINGS ==========
    namespace Heuristics {
        // Có cho phép heuristic-based detection không
        const bool ENABLE_HEURISTICS = true;

        // Độ nhạy cảm (0.0 - 1.0)
        // 0.0 = không sensitive (ít false positive)
        // 1.0 = rất sensitive (nhiều false positive)
        const double SENSITIVITY = 0.7;

        // Thread behavior analysis
        const bool ANALYZE_THREAD_BEHAVIOR = true;
        const bool ANALYZE_MEMORY_PATTERNS = true;
        const bool ANALYZE_REGISTRY_CHANGES = false;  // Requires additional privileges
    }

    // ========== OUTPUT FORMATTING ==========
    namespace Output {
        const bool USE_COLOR = true;
        const bool VERBOSE_MODE = false;
        const bool SHOW_CONFIDENCE = true;
        const bool SHOW_DETAIL_SCORES = true;
    }

    // ========== PERFORMANCE TUNING ==========
    namespace Performance {
        // Maximum file size to analyze (bytes)
        const unsigned long MAX_FILE_SIZE = 100 * 1024 * 1024;  // 100MB

        // Maximum memory to scan per process (bytes)
        const unsigned long MAX_MEMORY_SCAN_PER_PROCESS = 50 * 1024 * 1024;  // 50MB

        // Thread pool size for concurrent analysis
        const int THREAD_POOL_SIZE = 4;

        // Timeout for operations (milliseconds)
        const unsigned long OPERATION_TIMEOUT = 30000;  // 30 seconds
    }
}



#endif // PHANTOM_HUNTER_CONFIG_H