#include "FileScanner.h"
#include <fstream>
#include <stdexcept>
#include "../utils/HashUtil.h"


FileScanner::FileScanner(const std::string& dbPath) {
    // Load signatures database
    std::ifstream dbFile(dbPath);
    if (!dbFile.is_open()) {
        throw std::runtime_error("Failed to open signature database: " + dbPath);
    }

    std::string line;
    while (std::getline(dbFile, line)) {
        signatures.insert(line);
    }
}

bool FileScanner::scanFile(const std::string &filePath) const {
    // Compute the file's hash
    std::string fileHash = HashUtil::computeSHA256(filePath);

    // Check if the hash matches any signature
    return signatures.find(fileHash) != signatures.end();
}
