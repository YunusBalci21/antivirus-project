#include "ConsoleUI.h"
#include "../scanner/FileScanner.h"
#include "../utils/Logger.h"
#include <iostream>
#include <string>
#include <filesystem>
#include <windows.h>

void ConsoleUI::showMainMenu() {
    std::cout << "\n=== Antivirus Scanner ===\n"
              << "1. Scan File\n"
              << "2. Scan Directory\n"
              << "3. Enable Real-time Protection\n"
              << "4. View Quarantine\n"
              << "5. Update Signatures\n"
              << "6. Restore Quarantined File\n"
              << "7. Restore All Files\n"
              << "8. Exit\n"
              << "Choose an option: ";
}

void ConsoleUI::showScanProgress(const std::string& currentFile, int progress) {
    std::cout << "\rScanning: " << currentFile << " [";
    int barWidth = 50;
    int pos = barWidth * progress / 100;

    for (int i = 0; i < barWidth; ++i) {
        if (i < pos)
            std::cout << "=";
        else if (i == pos)
            std::cout << ">";
        else
            std::cout << " ";
    }
    std::cout << "] " << progress << "%" << std::flush;
}

void ConsoleUI::showScanResults(int totalFiles, int threats) {
    std::cout << "\n=== Scan Complete ===\n"
              << "Total files scanned: " << totalFiles << "\n"
              << "Threats detected: " << threats << "\n"
              << "=====================\n";
}

void ConsoleUI::unquarantineFile() {
    std::cout << "Enter the name of the quarantined file to restore: ";
    std::string filename;
    std::getline(std::cin, filename);
    if (filename.empty()) {
        std::cout << "Invalid file name.\n";
        return;
    }
    std::cout << "Restoring " << filename << " from quarantine...\n";
}

void ConsoleUI::unquarantineAll() {
    std::cout << "Restoring all files from quarantine...\n";
}

void ConsoleUI::clearScreen() {
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD coord = {0, 0};
    DWORD count;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hStdOut, &csbi);
    FillConsoleOutputCharacter(hStdOut, ' ',
                               csbi.dwSize.X * csbi.dwSize.Y, coord, &count);
    SetConsoleCursorPosition(hStdOut, coord);
}
