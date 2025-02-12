#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>
#include <chrono>
#include <iomanip>

class Logger {
public:
    static void logInfo(const std::string& message) {
        log(message, "INFO");
    }

    static void logWarning(const std::string& message) {
        log(message, "WARNING");
    }

    static void logError(const std::string& message) {
        log(message, "ERROR");
    }

    static void logDebug(const std::string& message) {
        log(message, "DEBUG");
    }

private:
    static void log(const std::string& message, const std::string& level) {
        std::ofstream logFile("logs/scan_results.log", std::ios::app);
        if (logFile.is_open()) {
            auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            logFile << "[" << std::put_time(std::localtime(&now), "%Y-%m-%d %H:%M:%S") << "] "
                   << level << ": " << message << std::endl;
        }
    }
};

#endif // LOGGER_H