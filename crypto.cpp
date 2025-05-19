#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <cstring>
#include <vector>
#include <cstdlib>

bool isValidKey(const std::string& key) {
    return key.size() == 32;
}

bool isValidIV(const std::string& iv) {
    return iv.size() == 16;
}

bool encryptAES256(const std::string& plaintext, std::string& ciphertext, const std::string& key, const std::string& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
        reinterpret_cast<const unsigned char*>(key.c_str()),
        reinterpret_cast<const unsigned char*>(iv.c_str())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    std::vector<unsigned char> out(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len, ciphertext_len;

    if (EVP_EncryptUpdate(ctx, out.data(), &len,
        reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, out.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ciphertext_len += len;
    ciphertext.assign(reinterpret_cast<char*>(out.data()), ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool decryptAES256(const std::string& ciphertext, std::string& plaintext, const std::string& key, const std::string& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
        reinterpret_cast<const unsigned char*>(key.c_str()),
        reinterpret_cast<const unsigned char*>(iv.c_str())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    std::vector<unsigned char> out(ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len, plaintext_len;

    if (EVP_DecryptUpdate(ctx, out.data(), &len,
        reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, out.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    plaintext_len += len;
    plaintext.assign(reinterpret_cast<char*>(out.data()), plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

std::string base64Encode(const std::string& binaryData) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bio);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, binaryData.data(), binaryData.size());
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(b64);
    return result;
}

std::string base64Decode(const std::string& base64Data) {
    BIO *bio, *b64;
    char* buffer = (char*)malloc(base64Data.size());
    memset(buffer, 0, base64Data.size());

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(base64Data.data(), base64Data.size());
    b64 = BIO_push(b64, bio);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    int decodedLen = BIO_read(b64, buffer, base64Data.size());

    std::string result(buffer, decodedLen);
    BIO_free_all(b64);
    free(buffer);
    return result;
}
