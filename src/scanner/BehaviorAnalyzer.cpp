#include "BehaviorAnalyzer.h"
#include "utils/Logger.h"
#include <algorithm>
#include "Config.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <vector>

BehaviorAnalyzer::BehaviorAnalyzer() {
    // Initialize any necessary resources
}

BehaviorAnalyzer::~BehaviorAnalyzer() {
    // Cleanup resources
}

bool BehaviorAnalyzer::analyze(const std::string& filePath) {
    try {
        // Analyze file behavior
        std::ifstream file(filePath, std::ios::binary);
        if (!file) {
            Logger::logError("Cannot open file for behavior analysis: " + filePath);
            return false;
        }

        std::vector<unsigned char> buffer(Config::SCAN_BUFFER_SIZE);
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        
        // Check for suspicious patterns
        if (scanForShellcode(buffer)) {
            Logger::logWarning("Shellcode detected in file: " + filePath);
            return true;
        }

        return false;
    } catch (const std::exception& e) {
        Logger::logError("Behavior analysis error: " + std::string(e.what()));
        return false;
    }
}

bool BehaviorAnalyzer::analyzeProcess(DWORD processId) {
    try {
        HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (processHandle == NULL) {
            Logger::logError("Failed to open process for analysis: " + std::to_string(processId));
            return false;
        }

        ProcessInfo info;
        info.pid = processId;

        // Get process name
        WCHAR processName[MAX_PATH];
        if (GetModuleBaseNameW(processHandle, NULL, processName, MAX_PATH)) {
            info.name = processName;
        }

        // Get loaded modules
        HMODULE modules[1024];
        DWORD needed;
        if (EnumProcessModules(processHandle, modules, sizeof(modules), &needed)) {
            DWORD moduleCount = needed / sizeof(HMODULE);
            for (DWORD i = 0; i < moduleCount; i++) {
                WCHAR moduleName[MAX_PATH];
                if (GetModuleFileNameExW(processHandle, modules[i], moduleName, MAX_PATH)) {
                    info.modules.push_back(moduleName);
                }
            }
        }

        bool result = isSuspiciousBehavior(info) ||
                     detectAPIHooks(processHandle) ||
                     checkProcessMemory(processHandle);

        CloseHandle(processHandle);
        return result;
    } catch (const std::exception& e) {
        Logger::logError("Process analysis error: " + std::string(e.what()));
        return false;
    }
}

bool BehaviorAnalyzer::isSuspiciousBehavior(const ProcessInfo& info) {
    // Check for suspicious API calls frequency
    for (const auto& [api, count] : info.apiCalls) {
        if (count > 1000) { // Threshold for suspicious number of API calls
            logSuspiciousActivity("High frequency API calls detected: " + api, info.pid);
            return true;
        }
    }

    // Check for suspicious loaded modules
    for (const auto& module : info.modules) {
        // Convert to lowercase for case-insensitive comparison
        std::wstring moduleLower = module;
        std::transform(moduleLower.begin(), moduleLower.end(), moduleLower.begin(), ::tolower);
        
        // Check for suspicious DLL names
        if (moduleLower.find(L"inject") != std::wstring::npos ||
            moduleLower.find(L"hook") != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

void BehaviorAnalyzer::logSuspiciousActivity(const std::string& activity, DWORD pid) {
    std::string message = "Process " + std::to_string(pid) + ": " + activity;
    Logger::logWarning(message);
}

bool BehaviorAnalyzer::checkProcessMemory(HANDLE processHandle) {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T address = 0;

    while (VirtualQueryEx(processHandle, (LPCVOID)address, &mbi, sizeof(mbi))) {
        // Check if memory region is executable
        if (mbi.State == MEM_COMMIT && 
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            
            // Read memory region
            std::vector<unsigned char> buffer(mbi.RegionSize);
            SIZE_T bytesRead;
            
            if (ReadProcessMemory(processHandle, mbi.BaseAddress, buffer.data(), 
                                mbi.RegionSize, &bytesRead)) {
                // Scan for suspicious patterns
                if (scanForShellcode(buffer)) {
                    return true;
                }
            }
        }
        
        // Move to next memory region
        address = (SIZE_T)mbi.BaseAddress + mbi.RegionSize;
    }

    return false;
}

bool BehaviorAnalyzer::detectAPIHooks(HANDLE processHandle) {
    try {
        // Check for API hooks in common DLLs
        std::vector<std::wstring> commonDlls = {L"kernel32.dll", L"user32.dll", L"ntdll.dll"};
        
        for (const auto& dll : commonDlls) {
            HMODULE module = GetModuleHandleW(dll.c_str());
            if (!module) continue;

            MODULEINFO moduleInfo;
            if (GetModuleInformation(processHandle, module, &moduleInfo, sizeof(moduleInfo))) {
                std::vector<unsigned char> buffer(moduleInfo.SizeOfImage);
                SIZE_T bytesRead;
                
                if (ReadProcessMemory(processHandle, moduleInfo.lpBaseOfDll, buffer.data(), 
                                    buffer.size(), &bytesRead)) {
                    // Check for hook signatures
                    // This is a simplified check - in practice, you'd want more sophisticated detection
                    for (size_t i = 0; i < buffer.size() - 5; i++) {
                        if (buffer[i] == 0xE9 || buffer[i] == 0xFF) { // JMP or CALL
                            Logger::logWarning("Potential API hook detected in " + 
                                             std::string(dll.begin(), dll.end()));
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    } catch (const std::exception& e) {
        Logger::logError("API hook detection error: " + std::string(e.what()));
        return false;
    }
}

bool BehaviorAnalyzer::scanForShellcode(const std::vector<unsigned char>& memory) {
    std::vector<std::vector<unsigned char>> patterns = {
        {0x33, 0xC0, 0x50, 0x68},  // XOR EAX, EAX; PUSH EAX; PUSH
        {0x55, 0x8B, 0xEC},        // PUSH EBP; MOV EBP, ESP
        {0x90, 0x90, 0x90, 0x90},  // NOP sled
        {0xE8, 0x00, 0x00, 0x00},  // CALL $+5
        {0xEB},                     // JMP SHORT
        {0xFF, 0xD0},              // CALL EAX
        {0xB8, 0x00, 0x00, 0x00}   // MOV EAX, immediate
    };

    // Add basic process injection detection
    const std::vector<std::string> suspiciousAPIs = {
        "VirtualAlloc",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "LoadLibraryA"
    };

    // Scan memory for patterns
    for (const auto& pattern : patterns) {
        for (size_t i = 0; i <= memory.size() - pattern.size(); i++) {
            if (std::equal(pattern.begin(), pattern.end(), memory.begin() + i)) {
                return true;
            }
        }
    }
    
    return false;
}