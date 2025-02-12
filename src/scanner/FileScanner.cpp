#include "FileScanner.h"
#include "../utils/HashUtil.h"
#include "../utils/Utils.h"
#include "../utils/Logger.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <atomic>
#include <cmath>
#include <vector>
#include <algorithm>
#include <windows.h>

FileScanner::FileScanner(const std::string& dbPath) {
    signatures = std::make_unique<SignatureDatabase>(dbPath);
}

bool FileScanner::scanFile(const std::string& filePath) const {
    try {
        if (!std::filesystem::exists(filePath)) {
            Logger::logError("File not found: " + filePath);
            return false;
        }

        // Check file hash
        std::string fileHash = HashUtil::computeSHA256(filePath);
        if (signatures->contains(fileHash)) {
            Logger::logWarning("Malicious file detected: " + filePath);
            return true;
        }

        // Perform heuristic analysis
        if (heuristicScan(filePath)) {
            Logger::logWarning("Suspicious behavior detected: " + filePath);
            return true;
        }

        return false;
    } catch (const std::exception& e) {
        Logger::logError("Error scanning file: " + std::string(e.what()));
        return false;
    }
}

bool FileScanner::heuristicScan(const std::string& filePath) const {
    try {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return false;

        // Calculate entropy
        std::vector<unsigned char> buffer(8192);
        size_t totalSize = 0;
        std::vector<int> byteFrequency(256, 0);
        float entropy = 0.0f;

        while (file.read(reinterpret_cast<char*>(buffer.data()), buffer.size())) {
            size_t bytesRead = file.gcount();
            totalSize += bytesRead;

            for (size_t i = 0; i < bytesRead; i++) {
                byteFrequency[buffer[i]]++;
            }
        }

        // Calculate entropy
        for (int frequency : byteFrequency) {
            if (frequency > 0) {
                float probability = static_cast<float>(frequency) / totalSize;
                entropy -= probability * std::log2f(probability);
            }
        }

        // Perform all checks
        return (entropy > 6.5f) ||          // High entropy
               checkPEFile(filePath) ||     // Suspicious PE characteristics
               Utils::isPacked(filePath) || // Packed executable detection
               Utils::containsSuspiciousStrings(filePath); // Known bad patterns
    } catch (const std::exception& e) {
        Logger::logError("Error in heuristic scan: " + std::string(e.what()));
        return false;
    }
}

bool FileScanner::scanDirectory(const std::string& dirPath) const {
    try {
        if (!std::filesystem::exists(dirPath)) {
            Logger::logError("Directory not found: " + dirPath);
            return false;
        }

        size_t fileCount = 0;
        size_t threatCount = 0;

        for (const auto& entry : std::filesystem::recursive_directory_iterator(dirPath)) {
            if (entry.is_regular_file()) {
                fileCount++;
                if (scanFile(entry.path().string())) {
                    threatCount++;
                    try {
                        std::string quarantinePath = "data/quarantine/" + 
                            entry.path().filename().string() + ".quarantine";
                        std::filesystem::create_directories("data/quarantine");
                        std::filesystem::rename(entry.path(), quarantinePath);
                        Logger::logInfo("File quarantined: " + quarantinePath);
                    } catch (const std::exception& e) {
                        Logger::logError("Failed to quarantine file: " + std::string(e.what()));
                    }
                }
            }
        }

        Logger::logInfo("Directory scan complete: " + 
                       std::to_string(fileCount) + " files scanned, " +
                       std::to_string(threatCount) + " threats found");

        return threatCount > 0;
    } catch (const std::exception& e) {
        Logger::logError("Error scanning directory: " + std::string(e.what()));
        return false;
    }
}

bool FileScanner::checkPEFile(const std::string& filePath) const {
    try {
        std::ifstream file(filePath, std::ios::binary);
        IMAGE_DOS_HEADER dosHeader;
        file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
        
        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return false;
        
        file.seekg(dosHeader.e_lfanew);
        IMAGE_NT_HEADERS ntHeader;
        file.read(reinterpret_cast<char*>(&ntHeader), sizeof(ntHeader));
        
        // Check for suspicious characteristics
        if ((ntHeader.FileHeader.Characteristics & IMAGE_FILE_DLL) ||
            (ntHeader.OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_UNKNOWN) ||
            (ntHeader.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) {
            Logger::logWarning("Suspicious PE characteristics detected: " + filePath);
            return true;
        }
        return false;
    } catch (...) {
        return false;
    }
}

void FileScanner::unquarantine(const std::string& filename) {
    try {
        std::string quarantinePath = "data/quarantine/" + filename;
        
        if (!std::filesystem::exists(quarantinePath)) {
            Logger::logError("Quarantined file not found: " + quarantinePath);
            std::cout << "Quarantined file not found.\n";
            return;
        }

        // Remove .quarantine extension
        std::string originalName = filename;
        const std::string quarantineExt = ".quarantine";
        if (originalName.length() >= quarantineExt.length() && 
            originalName.substr(originalName.length() - quarantineExt.length()) == quarantineExt) {
            originalName = originalName.substr(0, originalName.length() - quarantineExt.length());
        }

        // Create a unique destination path
        std::string destPath = createUniqueRestorePath(originalName);

        // Copy the file and preserve attributes
        std::filesystem::copy(quarantinePath, destPath, 
                            std::filesystem::copy_options::overwrite_existing);
        
        // Restore file permissions
        if (restoreFilePermissions(destPath)) {
            // Remove quarantined file only after successful restoration
            std::filesystem::remove(quarantinePath);
            Logger::logInfo("File restored successfully: " + destPath);
            std::cout << "File restored successfully to: " << destPath << "\n";
        } else {
            Logger::logWarning("File restored but permissions could not be fully restored: " + destPath);
            std::cout << "File restored but some permissions could not be restored.\n";
        }
    } catch (const std::exception& e) {
        Logger::logError("Error restoring file: " + std::string(e.what()));
        std::cout << "Error restoring file: " << e.what() << "\n";
    }
}

void FileScanner::unquarantineAll() {
    try {
        const std::string quarantinePath = "data/quarantine/";
        if (!std::filesystem::exists(quarantinePath)) {
            std::cout << "No files in quarantine.\n";
            return;
        }

        bool anyRestored = false;
        for (const auto& entry : std::filesystem::directory_iterator(quarantinePath)) {
            try {
                unquarantine(entry.path().filename().string());
                anyRestored = true;
            } catch (const std::exception& e) {
                Logger::logError("Error restoring file " + entry.path().string() + ": " + e.what());
                std::cout << "Error restoring " << entry.path().filename().string() << "\n";
            }
        }

        if (anyRestored) {
            std::cout << "Finished restoring files from quarantine.\n";
        } else {
            std::cout << "No files were restored from quarantine.\n";
        }
    } catch (const std::exception& e) {
        Logger::logError("Error during mass restoration: " + std::string(e.what()));
        std::cout << "Error restoring files: " << e.what() << "\n";
    }
}

bool FileScanner::restoreFilePermissions(const std::string& path) {
    try {
        // Convert string to wide string for Windows API
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
        std::wstring wpath(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &wpath[0], size_needed);

        DWORD attributes = GetFileAttributesW(wpath.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            return false;
        }
        
        // Remove any read-only or system attributes that might have been added
        attributes &= ~(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM);
        // Restore normal file attributes
        attributes |= FILE_ATTRIBUTE_NORMAL;
        
        if (!SetFileAttributesW(wpath.c_str(), attributes)) {
            Logger::logWarning("Failed to restore file attributes for: " + path);
            return false;
        }

        return true;
    } catch (...) {
        return false;
    }
}

std::string FileScanner::createUniqueRestorePath(const std::string& originalPath) {
    std::filesystem::path path(originalPath);
    std::string baseName = path.stem().string();
    std::string extension = path.extension().string();
    std::string destPath = originalPath;
    
    int counter = 1;
    while (std::filesystem::exists(destPath)) {
        destPath = baseName + "_restored_" + std::to_string(counter) + extension;
        counter++;
    }
    
    return destPath;
}

void FileScanner::updateSignatures() {
    Logger::logInfo("Updating signature database...");
}