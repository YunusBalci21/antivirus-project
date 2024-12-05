#ifndef FILESCANNER_H
#define FILESCANNER_H

#include <string>
#include <unordered_set>

class FileScanner {
public:
    FileScanner(const std::string &dbPath);
    bool scanFile(const std::string &filePath) const;

private:
    std::unordered_set<std::string> signatures; // Holds the hashes from the database
};

#endif // FILESCANNER_H
