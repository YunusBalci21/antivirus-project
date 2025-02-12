#ifndef SIGNATURE_DATABASE_H
#define SIGNATURE_DATABASE_H

#include <string>
#include <unordered_set>
#include <mutex>

class SignatureDatabase {
public:
    explicit SignatureDatabase(const std::string& dbPath);
    virtual ~SignatureDatabase() = default;  // Add virtual destructor
    
    bool contains(const std::string& hash) const;
    void addSignature(const std::string& hash);
    void loadSignatures(const std::string& dbPath);
    size_t getSignatureCount() const;

private:
    std::unordered_set<std::string> signatures;
    mutable std::mutex mutex;
    std::string dbPath;

    void saveSignatures() const;
};

#endif // SIGNATURE_DATABASE_H