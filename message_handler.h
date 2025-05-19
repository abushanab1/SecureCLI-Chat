#pragma once
#include <string>

bool writeMessage(const std::string& filename, const std::string& message);
std::string readMessage(const std::string& filename);
std::string getCurrentTimestamp();
