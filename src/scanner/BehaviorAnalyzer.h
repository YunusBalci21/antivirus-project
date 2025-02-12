#ifndef BEHAVIOR_ANALYZER_H
#define BEHAVIOR_ANALYZER_H

#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>

class BehaviorAnalyzer {
public:
    BehaviorAnalyzer();
    ~BehaviorAnalyzer();

    bool analyze(const std::string& filePath);
    bool analyzeProcess(DWORD processId);
    bool detectAPIHooks(HANDLE processHandle);
    bool monitorSystemCalls(DWORD processId);
    bool checkProcessMemory(HANDLE processHandle);

private:
    struct ProcessInfo {
        DWORD pid;
        std::wstring name;
        std::vector<std::wstring> modules;
        std::unordered_map<std::string, size_t> apiCalls;
    };

    bool isSuspiciousBehavior(const ProcessInfo& info);
    bool checkMemoryRegion(HANDLE process, MEMORY_BASIC_INFORMATION& mbi);
    bool scanForShellcode(const std::vector<unsigned char>& memory);
    void logSuspiciousActivity(const std::string& activity, DWORD pid);
};

#endif // BEHAVIOR_ANALYZER_H