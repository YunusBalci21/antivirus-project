#ifndef CONSOLE_UI_H
#define CONSOLE_UI_H

#include <string>

class ConsoleUI {
public:
    void showMainMenu();
    void showScanProgress(const std::string& currentFile, int progress);
    void showScanResults(int totalFiles, int threats);
    void scanFile();
    void scanDirectory();
    void toggleRealTimeProtection();
    void viewQuarantine();
    void updateSignatures();
    void unquarantineFile();
    void unquarantineAll();   

private:
    void clearScreen();
};

#endif // CONSOLE_UI_H
