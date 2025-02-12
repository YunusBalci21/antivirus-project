#include "AntivirusApp.h"
#include "scanner/FileScanner.h"
#include "scanner/RealTimeMonitor.h"
#include "ui/ConsoleUI.h"
#include "utils/Logger.h"
#include <iostream>
#include <string>
#include <filesystem>
#include <windows.h>

AntivirusApp::AntivirusApp()
    : scanner("data/signatures.db"),
      realTimeProtectionEnabled(false),
      running(true) {
    Logger::logInfo("Antivirus initialized");
}

void AntivirusApp::processCommand(const std::string& input) {
    if (input == "1") {
        std::cout << "Enter file path to scan: ";
        std::string filePath;
        std::getline(std::cin, filePath);

        if (std::filesystem::exists(filePath)) {
            scanSingleFile(filePath);
        } else {
            std::cout << "File does not exist.\n";
        }
    } 
    else if (input == "2") {
        std::cout << "Enter directory path to scan: ";
        std::string dirPath;
        std::getline(std::cin, dirPath);

        if (std::filesystem::exists(dirPath)) {
            scanDirectory(dirPath);
        } else {
            std::cout << "Directory does not exist.\n";
        }
    }
    else if (input == "3") {
        toggleRealTimeProtection();
    }
    else if (input == "4") {
        viewQuarantine();
    }
    else if (input == "5") {
        updateSignatures();
    }
    else if (input == "6") {
        viewQuarantine(); // Show available files first
        std::cout << "\nEnter the name of the file to restore (including .quarantine extension): ";
        std::string filename;
        std::getline(std::cin, filename);
        if (!filename.empty()) {
            scanner.unquarantine(filename);
        }
    }
    else if (input == "7") {
        std::cout << "Are you sure you want to restore all quarantined files? (y/n): ";
        std::string confirm;
        std::getline(std::cin, confirm);
        if (confirm == "y" || confirm == "Y") {
            scanner.unquarantineAll();
        }
    }
    else if (input == "8") {
        running = false;
    }
    else {
        std::cout << "Invalid option! Please try again.\n";
    }
}

void AntivirusApp::scanSingleFile(const std::string& path) {
    std::cout << "Scanning " << path << "...\n";
    bool threat = scanner.scanFile(path);

    if (threat) {
        std::cout << "Threat detected! Choose action:\n"
                  << "1. Quarantine\n"
                  << "2. Delete\n"
                  << "3. Ignore\n";

        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "1") {
            quarantineFile(path);
        } else if (choice == "2") {
            deleteFile(path);
        } else {
            std::cout << "File left unchanged.\n";
        }
    } else {
        std::cout << "No threats found.\n";
    }
}

void AntivirusApp::scanDirectory(const std::string& path) {
    std::cout << "Scanning directory " << path << "...\n";
    bool threatsFound = scanner.scanDirectory(path);

    if (threatsFound) {
        std::cout << "Threats were found during scan.\n";
    } else {
        std::cout << "No threats found.\n";
    }
}

void AntivirusApp::toggleRealTimeProtection() {
    if (!realTimeProtectionEnabled) {
        std::cout << "Starting real-time protection...\n";
        realTimeProtectionEnabled = true;
        monitor.startMonitoring(".", scanner);
        std::cout << "Real-time protection enabled.\n";
    } else {
        std::cout << "Stopping real-time protection...\n";
        realTimeProtectionEnabled = false;
        monitor.stopMonitoring();
        std::cout << "Real-time protection disabled.\n";
    }
}

void AntivirusApp::viewQuarantine() {
    const std::string quarantinePath = "data/quarantine/";
    std::cout << "\n=== Quarantined Files ===\n";

    if (!std::filesystem::exists(quarantinePath)) {
        std::cout << "No quarantined files found.\n";
        return;
    }

    int count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(quarantinePath)) {
        std::cout << ++count << ". " << entry.path().filename().string() << "\n";
    }

    if (count == 0) {
        std::cout << "No quarantined files found.\n";
    }
}

void AntivirusApp::updateSignatures() {
    std::cout << "Updating virus signatures...\n";
    scanner.updateSignatures();
    std::cout << "Signatures updated successfully.\n";
}

void AntivirusApp::quarantineFile(const std::string& path) {
    try {
        std::filesystem::create_directories("data/quarantine");
        std::string quarantinePath = "data/quarantine/" +
                                     std::filesystem::path(path).filename().string() +
                                     ".quarantine";
        std::filesystem::rename(path, quarantinePath);
        Logger::logInfo("File has been quarantined: " + quarantinePath);
        std::cout << "File has been quarantined.\n";
    } catch (const std::exception& e) {
        Logger::logError("Error quarantining file: " + std::string(e.what()));
        std::cout << "Error quarantining file: " << e.what() << "\n";
    }
}

void AntivirusApp::deleteFile(const std::string& path) {
    try {
        std::filesystem::remove(path);
        Logger::logInfo("File has been deleted: " + path);
        std::cout << "File has been deleted.\n";
    } catch (const std::exception& e) {
        Logger::logError("Error deleting file: " + std::string(e.what()));
        std::cout << "Error deleting file: " << e.what() << "\n";
    }
}

void AntivirusApp::run() {
    Logger::logInfo("Starting antivirus application");

    while (running) {
        try {
            ui.showMainMenu();
            std::string input;
            std::getline(std::cin, input);
            processCommand(input);
        } catch (const std::exception& e) {
            Logger::logError("Error: " + std::string(e.what()));
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }
}