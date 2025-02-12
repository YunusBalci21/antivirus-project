#include "Utils.h"
#include <fstream>
#include <sstream>
#include <iterator>
#include <filesystem>
#include <vector>
#include <algorithm>
#include <windows.h>
#include <shellapi.h>
#include <cmath>

namespace Utils {
    namespace {
        // Helper function for string searching
        bool containsPattern(const std::string& content, const std::vector<std::string>& patterns) {
            for (const auto& pattern : patterns) {
                if (content.find(pattern) != std::string::npos) {
                    return true;
                }
            }
            return false;
        }
    }

    bool ends_with(const std::string& str, const std::string& suffix) {
        if (str.length() < suffix.length()) {
            return false;
        }
        return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
    }

    float calculateEntropy(const std::string& content) {
        if (content.empty()) return 0.0f;

        std::vector<int> frequencies(256, 0);
        for (unsigned char c : content) {
            frequencies[c]++;
        }

        float entropy = 0.0f;
        float contentSize = static_cast<float>(content.size());

        for (int frequency : frequencies) {
            if (frequency > 0) {
                float probability = frequency / contentSize;
                entropy -= probability * std::log2(probability);
            }
        }

        return entropy;
    }

    std::string getFileType(const std::string& filePath) {
        SHFILEINFOW fileInfo = {0};
        std::wstring widePath(filePath.begin(), filePath.end());
        
        DWORD_PTR result = SHGetFileInfoW(
            widePath.c_str(),
            0,
            &fileInfo,
            sizeof(fileInfo),
            SHGFI_TYPENAME
        );

        if (result == 0) return "";
        
        std::wstring fileType(fileInfo.szTypeName);
        return std::string(fileType.begin(), fileType.end());
    }

    bool isExecutable(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return false;

        char magic[2];
        file.read(magic, 2);
        
        // Check for MZ header (DOS/PE executable)
        if (magic[0] == 'M' && magic[1] == 'Z') return true;
        
        return false;
    }

    bool isPacked(const std::string& filePath) {
        // Check for common packer signatures
        const std::vector<std::string> packerSigs = {
            "UPX!", "ASPack", "FSG!", "PECompact", "MEW", "MPRESS", 
            "PACK", "Themida", "Obsidium", "VMProtect"
        };

        std::ifstream file(filePath, std::ios::binary);
        std::string content((std::istreambuf_iterator<char>(file)), 
                           std::istreambuf_iterator<char>());

        return containsPattern(content, packerSigs);
    }

    bool containsSuspiciousStrings(const std::string& filePath) {
        // Malicious patterns by category
        const std::vector<std::string> processPatterns = {
            "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
            "OpenProcess", "CreateProcess", "ShellExecute", "WinExec",
            "SetWindowsHookEx", "GetAsyncKeyState", "RegisterHotKey"
        };

        const std::vector<std::string> networkPatterns = {
            "WSAStartup", "socket", "connect", "InternetOpen",
            "HttpSendRequest", "URLDownloadToFile", "InternetReadFile"
        };

        const std::vector<std::string> filePatterns = {
            "CreateFile", "WriteFile", "CopyFile", "MoveFile",
            "DeleteFile", "RegCreateKey", "RegSetValue"
        };

        const std::vector<std::string> antiAnalysisPatterns = {
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "OutputDebugString", "GetTickCount", "QueryPerformanceCounter"
        };

        const std::vector<std::string> injectionPatterns = {
            "VirtualProtect", "VirtualAlloc", "LoadLibrary",
            "GetProcAddress", "CreateThread", "CreateMutex"
        };

        const std::vector<std::string> spywarePatterns = {
            "GetForegroundWindow", "GetKeyState", "GetClipboardData",
            "SetClipboardData", "GetWindowText", "BitBlt", "GetDC"
        };

        const std::vector<std::string> ransomwarePatterns = {
            "CryptEncrypt", "CryptDecrypt", "CryptGenKey",
            "BCryptEncrypt", "BCryptDecrypt", "wincrypt.h"
        };

        std::ifstream file(filePath, std::ios::binary);
        if (!file) return false;

        std::string content((std::istreambuf_iterator<char>(file)), 
                           std::istreambuf_iterator<char>());

        // Check for encoded/obfuscated content
        std::string base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        size_t base64Count = 0;
        const size_t BASE64_THRESHOLD = 100;

        for (char c : content) {
            if (base64Chars.find(c) != std::string::npos) {
                base64Count++;
                if (base64Count > BASE64_THRESHOLD) {
                    return true;
                }
            }
        }

        // Check all pattern categories
        return containsPattern(content, processPatterns) ||
               containsPattern(content, networkPatterns) ||
               containsPattern(content, filePatterns) ||
               containsPattern(content, antiAnalysisPatterns) ||
               containsPattern(content, injectionPatterns) ||
               containsPattern(content, spywarePatterns) ||
               containsPattern(content, ransomwarePatterns);
    }
}