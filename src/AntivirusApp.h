#ifndef ANTIVIRUS_APP_H
#define ANTIVIRUS_APP_H

#include "scanner/FileScanner.h"
#include "scanner/RealTimeMonitor.h"
#include "ui/ConsoleUI.h"
#include <string>

class AntivirusApp {
private:
    FileScanner scanner;
    RealTimeMonitor monitor;
    ConsoleUI ui;
    bool realTimeProtectionEnabled;
    bool running;

    void processCommand(const std::string& input);
    void scanSingleFile(const std::string& path);
    void scanDirectory(const std::string& path);
    void toggleRealTimeProtection();
    void viewQuarantine();
    void updateSignatures();
    void quarantineFile(const std::string& path);
    void deleteFile(const std::string& path);

public:
    AntivirusApp();
    void run();
};

#endif // ANTIVIRUS_APP_H