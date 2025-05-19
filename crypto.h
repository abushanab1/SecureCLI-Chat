#pragma once
#include <string>

bool encryptAES256(const std::string& plaintext, std::string& ciphertext, const std::string& key, const std::string& iv);
bool decryptAES256(const std::string& ciphertext, std::string& plaintext, const std::string& key, const std::string& iv);
bool isValidKey(const std::string& key);
bool isValidIV(const std::string& iv);
std::string base64Encode(const std::string& binaryData);
std::string base64Decode(const std::string& base64Data);
