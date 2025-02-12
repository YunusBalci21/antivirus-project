#include "RealTimeMonitor.h"
#include "../utils/Logger.h"
#include <windows.h>
#include <algorithm>
#include <iterator>
#include <thread>
#include <vector>
#include <chrono>
#include <codecvt>
#include <locale>
#include <iostream>
#include <fstream>
#include <array>
#include <cmath>

namespace fs = std::filesystem;

RealTimeMonitor::RealTimeMonitor() : running(false), dirHandle(INVALID_HANDLE_VALUE) {}

RealTimeMonitor::~RealTimeMonitor() {
    stopMonitoring();
}

void RealTimeMonitor::startMonitoring(const std::string& directoryPath, FileScanner& scanner) {
    if (running) {
        Logger::logWarning("Monitor is already running");
        return;
    }

    if (dirHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(dirHandle);
        dirHandle = INVALID_HANDLE_VALUE;
    }

    fs::path normPath = fs::absolute(directoryPath);
    std::string cleanPath = normPath.string();

    // Convert to wide string
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, cleanPath.c_str(), -1, nullptr, 0);
    std::wstring wideDirPath(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, cleanPath.c_str(), -1, &wideDirPath[0], size_needed);

    dirHandle = CreateFileW(
        wideDirPath.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        nullptr
    );

    if (dirHandle == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        Logger::logError("Failed to open directory (Error " + std::to_string(err) + "): " + cleanPath);
        return;
    }

    running = true;
    monitorThread = std::thread(&RealTimeMonitor::monitorDirectory, this, cleanPath, std::ref(scanner));
    Logger::logInfo("Real-time monitoring started for: " + cleanPath);
}

void RealTimeMonitor::stopMonitoring() {
    if (!running) return;

    running = false;
    
    if (dirHandle != INVALID_HANDLE_VALUE) {
        CancelIo(dirHandle);
        CloseHandle(dirHandle);
        dirHandle = INVALID_HANDLE_VALUE;
    }

    if (monitorThread.joinable()) {
        monitorThread.join();
    }

    Logger::logInfo("Real-time monitoring stopped");
}

void RealTimeMonitor::monitorDirectory(const std::string& path, FileScanner& scanner) {
    const DWORD bufferSize = 4096;
    std::vector<BYTE> buffer(bufferSize);
    OVERLAPPED overlapped = {0};
    overlapped.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);

    while (running) {
        DWORD bytesReturned = 0;
        if (!ReadDirectoryChangesW(
            dirHandle,
            buffer.data(),
            bufferSize,
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_SIZE |
            FILE_NOTIFY_CHANGE_LAST_WRITE |
            FILE_NOTIFY_CHANGE_SECURITY,
            &bytesReturned,
            &overlapped,
            nullptr))
        {
            DWORD err = GetLastError();
            if (err != ERROR_IO_PENDING) {
                Logger::logError("ReadDirectoryChangesW failed: " + std::to_string(err));
                break;
            }
        }

        DWORD waitResult = WaitForSingleObject(overlapped.hEvent, 1000);
        if (waitResult == WAIT_OBJECT_0) {
            if (GetOverlappedResult(dirHandle, &overlapped, &bytesReturned, FALSE)) {
                if (bytesReturned > 0) {
                    FILE_NOTIFY_INFORMATION* notification = 
                        reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer.data());

                    do {
                        std::wstring fileName(
                            notification->FileName,
                            notification->FileNameLength / sizeof(WCHAR)
                        );

                        // Convert to UTF-8
                        int utf8Size = WideCharToMultiByte(
                            CP_UTF8, 0,
                            fileName.c_str(), static_cast<int>(fileName.size()),
                            nullptr, 0, nullptr, nullptr
                        );
                        
                        std::string strFileName(utf8Size, 0);
                        WideCharToMultiByte(
                            CP_UTF8, 0,
                            fileName.c_str(), static_cast<int>(fileName.size()),
                            &strFileName[0], utf8Size,
                            nullptr, nullptr
                        );

                        fs::path fullPath(path);
                        fullPath /= strFileName;
                        std::string filePath = fullPath.lexically_normal().string();

                        Logger::logInfo("Detected change: " + filePath);
                        handleFileChange(filePath, scanner);

                        if (notification->NextEntryOffset == 0) break;
                        notification = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                            reinterpret_cast<BYTE*>(notification) + 
                            notification->NextEntryOffset);
                    } while (running);
                }
            }
            ResetEvent(overlapped.hEvent);
        }
    }

    CloseHandle(overlapped.hEvent);
}

void RealTimeMonitor::handleFileChange(const std::string& filePath, FileScanner& scanner) {
    try {
        // More aggressive retry strategy for file access
        bool fileReady = false;
        for (int i = 0; i < 10; ++i) {
            if (fs::exists(filePath)) {
                std::error_code ec;
                auto fileSize = fs::file_size(filePath, ec);
                if (!ec && fileSize > 0) {
                    fileReady = true;
                    break;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (!fileReady || !fs::exists(filePath)) return;

        // Enhanced system file protection
        const std::vector<std::string> excludedPatterns = {
            "\\windows\\", "\\program files\\", "\\programdata\\", 
            "\\appdata\\", "\\temp\\", "\\.quarantine", "\\logs\\",
            "\\system32\\", "\\syswow64\\", "\\.dll", "\\.sys",
            "scan_results.log", "signatures.db", "\\.git\\",
            "\\node_modules\\", "\\packages\\"
        };

        std::string lowerPath = filePath;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);
        
        bool isSystemFile = false;
        for (const auto& pattern : excludedPatterns) {
            if (lowerPath.find(pattern) != std::string::npos) {
                Logger::logInfo("System file detected: " + filePath);
                isSystemFile = true;
                break;
            }
        }

        // Enhanced extension checking
        std::string ext = fs::path(filePath).extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        
        const std::vector<std::string> highRiskExts = {
            ".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ws", ".wsf", ".wsh",
            ".ps1", ".msi", ".msp", ".hta", ".jar", ".py", ".pyw", ".com", ".msc", ".cpl",
            ".reg", ".inf", ".scf", ".url", ".lnk", ".job", ".jse", ".pif", ".application"
        };

        // Immediate aggressive scan for high-risk files
        if (std::find(highRiskExts.begin(), highRiskExts.end(), ext) != highRiskExts.end() || !isSystemFile) {
            // Check file entropy for potential encryption/packing
            if (checkFileEntropy(filePath)) {
                Logger::logWarning("High entropy detected in file: " + filePath);
                quarantineFile(filePath);
                return;
            }

            if (scanner.scanFile(filePath)) {
                Logger::logWarning("Threat detected: " + filePath);
                quarantineFile(filePath);
                return;
            }

            behaviorAnalyzer.analyze(filePath);
        }

        // Enhanced ransomware detection
        auto now = std::chrono::steady_clock::now();
        auto it = this->lastChange.find(filePath);
        if (it != this->lastChange.end()) {
            auto duration = now - it->second;
            if (duration < std::chrono::minutes(1)) {
                if (++this->fileChangeCount[filePath] > 5) {
                    if (checkSurroundingFilesForChanges(filePath)) {
                        Logger::logWarning("Ransomware behavior detected: " + filePath);
                        quarantineFile(filePath);
                        return;
                    }
                }
            } else {
                this->fileChangeCount[filePath] = 1;
            }
        } else {
            this->fileChangeCount[filePath] = 1;
        }
        this->lastChange[filePath] = now;

    } catch (const std::exception& e) {
        Logger::logError("File change error: " + std::string(e.what()));
    }
}

bool RealTimeMonitor::checkFileEntropy(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) return false;

    std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(file), {});
    if (buffer.empty()) return false;

    std::array<int, 256> frequencies = {0};
    for (unsigned char byte : buffer) {
        frequencies[byte]++;
    }

    double entropy = 0.0;
    for (int freq : frequencies) {
        if (freq == 0) continue;
        double probability = static_cast<double>(freq) / buffer.size();
        entropy -= probability * std::log2(probability);
    }

    return entropy > 7.0;
}

bool RealTimeMonitor::checkSurroundingFilesForChanges(const std::string& filePath) {
    try {
        fs::path path(filePath);
        fs::path dir = path.parent_path();
        int changedFiles = 0;
        
        for (const auto& entry : fs::directory_iterator(dir)) {
            auto it = this->lastChange.find(entry.path().string());
            if (it != this->lastChange.end()) {
                changedFiles++;
                if (changedFiles > 3) {
                    return true;
                }
            }
        }
    } catch (...) {
        Logger::logError("Error checking surrounding files");
    }
    return false;
}

void RealTimeMonitor::quarantineFile(const std::string& filePath) {
    try {
        fs::path source(filePath);
        fs::path quarantineDir = ".quarantine";
        fs::path target = quarantineDir / source.filename();

        if (!fs::exists(quarantineDir)) {
            fs::create_directories(quarantineDir);
        }

        // Handle duplicate filenames
        int counter = 0;
        while (fs::exists(target)) {
            target = quarantineDir / 
                    (source.stem().string() + 
                     "_" + std::to_string(++counter) + 
                     source.extension().string());
        }

        fs::rename(source, target);
        Logger::logInfo("Quarantined: " + filePath + " -> " + target.string());
        std::cout << "\n[!] QUARANTINED: " << filePath << "\n";
    } catch (const std::exception& e) {
        Logger::logError("Quarantine failed: " + std::string(e.what()));
    }
}