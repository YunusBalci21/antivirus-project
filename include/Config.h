#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <vector>
#include <filesystem>

namespace Config {
    // File paths
    const std::string SIGNATURE_DB_PATH = "data/signatures.db";
    const std::string QUARANTINE_PATH = "data/quarantine/";
    const std::string LOG_PATH = "logs/scan_results.log";

    // Scan settings
    const size_t SCAN_BUFFER_SIZE = 8192;
    const float ENTROPY_THRESHOLD = 7.0f;
    const size_t MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB
    const int SCAN_THREADS = 4;

    // Monitor settings
    const int MONITOR_INTERVAL_MS = 100;
    const size_t MAX_PROCESS_MEMORY = 1024 * 1024 * 1024; // 1GB
    
    // Suspicious file extensions
    const std::vector<std::string> SUSPICIOUS_EXTENSIONS = {
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js"
    };

    // Suspicious API calls
    const std::vector<std::string> SUSPICIOUS_APIS = {
        "CreateRemoteThread",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "SetWindowsHookEx",
        "WSAConnect"
    };

    // Network monitoring
    const int NETWORK_BUFFER_SIZE = 65536;
    const std::vector<int> MONITORED_PORTS = {80, 443, 445, 3389, 4444, 8080};
}

#endif // CONFIG_H