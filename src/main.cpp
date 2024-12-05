#include <iostream>
#include "utils/HashUtil.h"
#include "scanner/FileScanner.h"

int main() {
    std::string testFile = "testfile.txt";
    std::string signatureDB = "data/signatures.db";

    try {
        // Compute SHA-256 hash
        std::string hash = HashUtil::computeSHA256(testFile);
        std::cout << "SHA-256 hash of " << testFile << ": " << hash << std::endl;

        // Scan file using FileScanner
        FileScanner scanner(signatureDB);
        bool isThreat = scanner.scanFile(testFile);
        
        if (isThreat) {
            std::cout << "Threat detected in file: " << testFile << std::endl;
        } else {
            std::cout << "File is safe: " << testFile << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
