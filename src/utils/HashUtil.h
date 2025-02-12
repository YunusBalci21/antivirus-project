#ifndef HASH_UTIL_H
#define HASH_UTIL_H

#include <string>

class HashUtil {
public:
    static std::string computeSHA256(const std::string& filePath);
    static std::string computeMD5(const std::string& filePath);
};

#endif // HASH_UTIL_H