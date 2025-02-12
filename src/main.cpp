#include "AntivirusApp.h"
#include "utils/Logger.h"
#include <windows.h>
#include <filesystem>
#include <iostream>  // For std::cerr
#include <exception>

int main() {
    try {
        // Set console output to UTF-8
        SetConsoleOutputCP(CP_UTF8);
        
        // Create necessary directories
        std::filesystem::create_directories("data");
        std::filesystem::create_directories("data/quarantine");
        std::filesystem::create_directories("logs");

        AntivirusApp app;
        app.run();
        
        return 0;
    } catch (const std::exception& e) {
        Logger::logError("Fatal error: " + std::string(e.what()));
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
}