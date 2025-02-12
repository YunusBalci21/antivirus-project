#ifndef UTILS_H
#define UTILS_H

#include <string>

namespace Utils {
    bool ends_with(const std::string& str, const std::string& suffix);
    float calculateEntropy(const std::string& content);
    std::string getFileType(const std::string& filePath);
    bool isExecutable(const std::string& filePath);
    bool isPacked(const std::string& filePath);              // Add this
    bool containsSuspiciousStrings(const std::string& filePath); // Add this
}

#endif // UTILS_H