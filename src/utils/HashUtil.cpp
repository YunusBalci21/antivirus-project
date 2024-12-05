#include "HashUtil.h"
#include <openssl/evp.h>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <iomanip>

std::string HashUtil::computeSHA256(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + filePath);
    }

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (!context) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    const EVP_MD* md = EVP_sha256();
    if (EVP_DigestInit_ex(context, md, nullptr) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("Failed to initialize digest context");
    }

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        if (EVP_DigestUpdate(context, buffer, file.gcount()) != 1) {
            EVP_MD_CTX_free(context);
            throw std::runtime_error("Failed to update digest");
        }
    }

    // Handle remaining data
    if (file.gcount() > 0) {
        if (EVP_DigestUpdate(context, buffer, file.gcount()) != 1) {
            EVP_MD_CTX_free(context);
            throw std::runtime_error("Failed to update digest");
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    if (EVP_DigestFinal_ex(context, hash, &length) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("Failed to finalize digest");
    }

    EVP_MD_CTX_free(context);

    std::ostringstream oss;
    for (unsigned int i = 0; i < length; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str();
}
