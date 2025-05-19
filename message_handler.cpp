#include "message_handler.h"
#include <fstream>
#include <chrono>
#include <ctime>

std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t timeNow = std::chrono::system_clock::to_time_t(now);
    char buf[100];
    std::strftime(buf, sizeof(buf), "[%Y-%m-%d %H:%M:%S]", std::localtime(&timeNow));
    return std::string(buf);
}

bool writeMessage(const std::string& filename, const std::string& message) {
    std::ofstream outfile(filename, std::ios::app);
    if (!outfile) return false;

    outfile << getCurrentTimestamp() << "\n";
    outfile << message << "\n";
    outfile << "---\n";
    return true;
}

std::string readMessage(const std::string& filename) {
    std::ifstream infile(filename);
    if (!infile) return "";

    std::string line, all;
    while (std::getline(infile, line)) {
        all += line + "\n";
    }
    return all;
}
