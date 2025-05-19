#include <iostream>
#include <sstream>
#include "message_handler.h"
#include "crypto.h"

int main() {
    std::string mode;
    std::cout << "Mode (send/receive): ";
    std::getline(std::cin, mode);

    std::string key, iv;
    std::cout << "Enter 32-byte key: ";
    std::getline(std::cin, key);
    if (!isValidKey(key)) {
        std::cerr << "Key must be 32 characters (256-bit)\n";
        return 1;
    }

    std::cout << "Enter 16-byte IV: ";
    std::getline(std::cin, iv);
    if (!isValidIV(iv)) {
        std::cerr << "IV must be 16 characters (128-bit)\n";
        return 1;
    }

    if (mode == "send") {
        std::string input;
        std::cout << "Enter your message: ";
        std::getline(std::cin, input);

        std::string encrypted;
        if (!encryptAES256(input, encrypted, key, iv)) {
            std::cerr << "Encryption failed.\n";
            return 1;
        }

        std::string encoded = base64Encode(encrypted);
        if (!writeMessage("chat.txt", encoded)) {
            std::cerr << "Failed to write message.\n";
            return 1;
        }

        std::cout << "Message sent (encrypted).\n";

    } else if (mode == "receive") {
        std::string allMessages = readMessage("chat.txt");
        if (allMessages.empty()) {
            std::cerr << "No messages to read.\n";
            return 1;
        }

        std::istringstream stream(allMessages);
        std::string line, block;
        while (std::getline(stream, line)) {
            if (line == "---") {
                std::istringstream blockStream(block);
                std::string timestamp;
                std::getline(blockStream, timestamp);
                std::string encoded((std::istreambuf_iterator<char>(blockStream)),
                                    std::istreambuf_iterator<char>());

                std::string decoded = base64Decode(encoded);
                std::string decrypted;
                if (decryptAES256(decoded, decrypted, key, iv)) {
                    std::cout << timestamp << " " << decrypted << "\n";
                } else {
                    std::cout << timestamp << " [Decryption failed]\n";
                }

                block.clear();
            } else {
                block += line + "\n";
            }
        }

    } else {
        std::cerr << "Invalid mode. Use 'send' or 'receive'.\n";
        return 1;
    }

    return 0;
}
