#ifndef REAL_TIME_MONITOR_H
#define REAL_TIME_MONITOR_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <thread>
#include <atomic>
#include <unordered_map>
#include <chrono>
#include <filesystem>
#include "FileScanner.h"
#include "BehaviorAnalyzer.h"
#include "../utils/Logger.h"

namespace fs = std::filesystem;

class RealTimeMonitor {
public:
    RealTimeMonitor();
    ~RealTimeMonitor();

    void startMonitoring(const std::string& directoryPath, FileScanner& scanner);
    void stopMonitoring();

private:
    std::atomic<bool> running;
    std::thread monitorThread;
    HANDLE dirHandle;
    BehaviorAnalyzer behaviorAnalyzer;
    
    // File change tracking
    std::unordered_map<std::string, int> fileChangeCount;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> lastChange;

    void monitorDirectory(const std::string& path, FileScanner& scanner);
    void handleFileChange(const std::string& filePath, FileScanner& scanner);
    void quarantineFile(const std::string& filePath);
    bool checkFileEntropy(const std::string& filePath);
    bool checkSurroundingFilesForChanges(const std::string& filePath);
};

#endif // REAL_TIME_MONITOR_H