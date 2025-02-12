#ifndef FILE_SCANNER_H
#define FILE_SCANNER_H

#include "SignatureDatabase.h"
#include <string>
#include <memory>
#include <chrono>
#include <thread>
#include <windows.h>

class FileScanner {
public:
    explicit FileScanner(const std::string& dbPath);
    virtual ~FileScanner() = default;

    bool scanFile(const std::string& filePath) const;
    bool scanDirectory(const std::string& dirPath) const;
    void unquarantineAll();
    void unquarantine(const std::string& filename);
    void updateSignatures();

private:
    std::unique_ptr<SignatureDatabase> signatures;
    
    bool heuristicScan(const std::string& filePath) const;
    bool scanFileContent(const std::string& filePath) const;
    bool isFileTypeSupported(const std::string& filePath) const;
    bool checkPEFile(const std::string& filePath) const;
    void logScanResult(const std::string& filePath, bool threat) const;
    bool restoreFilePermissions(const std::string& path);
    std::string createUniqueRestorePath(const std::string& originalPath);
};

#endif // FILE_SCANNER_H