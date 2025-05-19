# SecureCLI Chat

SecureCLI Chat is a lightweight, command-line messaging tool built in C++ to simulate encrypted communication using AES-256 (via OpenSSL). Designed for Unix-based systems, it demonstrates core concepts of secure message exchange, file I/O, and cryptographic key management.

## 🚀 Features

- 🔐 AES-256-CBC encryption/decryption using OpenSSL
- 💬 Send/receive mode simulation via encrypted file exchange
- 🔑 Shared key and IV input for secure communication
- 🕒 Timestamped messages with multi-message history
- 🧾 Base64 encoding for safe file storage of binary ciphertext
- 🧠 Minimal dependencies (just OpenSSL)

## 🧱 Technologies

- C++11
- OpenSSL (`libssl-dev` or `brew install openssl`)
- Unix/Linux-compatible terminal

## 🛠 How to Build

```bash
g++ -std=c++11 main.cpp message_handler.cpp crypto.cpp -o securecli -lssl -lcrypto
