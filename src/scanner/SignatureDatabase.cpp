#include "SignatureDatabase.h"
#include "../utils/Logger.h"
#include <fstream>
#include <algorithm>
#include <filesystem>

SignatureDatabase::SignatureDatabase(const std::string& dbPath) : dbPath(dbPath) {
    loadSignatures(dbPath);
}

bool SignatureDatabase::contains(const std::string& hash) const {
    std::lock_guard<std::mutex> lock(mutex);
    return signatures.find(hash) != signatures.end();
}

void SignatureDatabase::addSignature(const std::string& hash) {
    std::lock_guard<std::mutex> lock(mutex);
    signatures.insert(hash);
    saveSignatures();
}

void SignatureDatabase::loadSignatures(const std::string& dbPath) {
    std::lock_guard<std::mutex> lock(mutex);
    signatures.clear();

    try {
        if (!std::filesystem::exists(dbPath)) {
            Logger::logWarning("Signature database not found, creating new one: " + dbPath);
            std::ofstream newDb(dbPath);
            return;
        }

        std::ifstream file(dbPath);
        std::string line;
        
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#') continue;
            
            line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());
            
            if (!line.empty()) {
                signatures.insert(line);
            }
        }

        Logger::logInfo("Loaded " + std::to_string(signatures.size()) + " signatures");
    } catch (const std::exception& e) {
        Logger::logError("Error loading signatures: " + std::string(e.what()));
        throw;
    }
}

void SignatureDatabase::saveSignatures() const {
    try {
        std::ofstream file(dbPath, std::ios::out | std::ios::trunc);
        for (const auto& signature : signatures) {
            file << signature << '\n';
        }
    } catch (const std::exception& e) {
        Logger::logError("Error saving signatures: " + std::string(e.what()));
        throw;
    }
}

size_t SignatureDatabase::getSignatureCount() const {
    std::lock_guard<std::mutex> lock(mutex);
    return signatures.size();
}