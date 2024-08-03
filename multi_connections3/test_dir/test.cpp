
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <string>
#include <cstring>
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/evp.h>

#define KEY_SIZE 32
#define IV_SIZE 16

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int aes_encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv, unsigned char* ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating context." << std::endl;
        return -1;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        std::cerr << "Error initializing encryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        std::cerr << "Error during encryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        std::cerr << "Error during final encryption step." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int aes_decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating context." << std::endl;
        return -1;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        std::cerr << "Error initializing decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        std::cerr << "Error during decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int plaintext_len = len;

    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if (ret != 1) {
        std::cerr << "Error during final decryption step." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

void bin_to_hex(const unsigned char* bin, int bin_len, char* hex) {
    for (int i = 0; i < bin_len; ++i) {
        sprintf(hex + (i * 2), "%02x", bin[i]);
    }
    hex[bin_len * 2] = '\0'; // Null-terminate the string
}

void send_key_iv(SSL* ssl, int port, const unsigned char* key, int key_len, const unsigned char* iv, int iv_len) {
    // Buffer to hold the hex representations and the final message
    const int HEX_KEY_SIZE = key_len * 2 + 1; // 2 chars per byte + null terminator
    const int HEX_IV_SIZE = iv_len * 2 + 1;  // 2 chars per byte + null terminator
    char hex_key[HEX_KEY_SIZE];
    char hex_iv[HEX_IV_SIZE];

    // Convert key and IV to hex
    bin_to_hex(key, key_len, hex_key);
    bin_to_hex(iv, iv_len, hex_iv);

    // Buffer to hold the final message
    const int MSG_SIZE = 1024;
    char msg[MSG_SIZE];

    // Format the message
    snprintf(msg, MSG_SIZE, "k;%d;%s;%s;", port, hex_key, hex_iv);
    printf("msg: %s\n", msg);
    // Send the message over TLS
    int bytes_written = SSL_write(ssl, msg, strlen(msg));
    if (bytes_written <= 0) {
        // Handle error
        std::cerr << "Error writing to SSL connection." << std::endl;
        return;
        //exit(EXIT_FAILURE);
    }
}

// Helper function to convert hex string to binary data
void hex_to_bin(const char* hex, unsigned char* bin, int bin_len) {
    for (int i = 0; i < bin_len; ++i) {
        sscanf(hex + 2*i, "%2hhx", &bin[i]);
    }
}

// Function to receive and parse the message
bool receive_key_iv(char* msg, unsigned char* port, unsigned char* key, int key_len, unsigned char* iv, int iv_len) {
    const int MSG_SIZE = 1024;
    // Parse the message
    char* token = strtok(msg, ";");
    if (token == nullptr || strcmp(token, "k") != 0) {
        std::cerr << "Invalid message format." << std::endl;
        return false;
    }

    // Get port
    token = strtok(nullptr, ";");
    if (token == nullptr) {
        std::cerr << "Missing port in message." << std::endl;
        return false;
    }
    port = (unsigned char*) token;

    // Get key
    token = strtok(nullptr, ";");
    if (token == nullptr || strlen(token) != key_len * 2) {
        std::cerr << "Invalid key length in message." << std::endl;
        return false;
    }
    hex_to_bin(token, key, key_len);

    // Get IV
    token = strtok(nullptr, ";");
    if (token == nullptr || strlen(token) != iv_len * 2) {
        std::cerr << "Invalid IV length in message." << std::endl;
        return false;
    }
    hex_to_bin(token, iv, iv_len);

    return true;
}

void generate_symmetric_key(unsigned char* key, int size) {
    if (!RAND_bytes(key, size)) {
        std::cerr << "Error generating random bytes." << std::endl;
        exit(EXIT_FAILURE);
    }

    // For debugging: Print the key in hex format
    std::cout << "Generated Key: ";
    for (int i = 0; i < size; ++i) {
        printf("%02x", key[i]);
    }
    std::cout << std::endl;
}

int main(){
    char msg[1024];
    unsigned char plaintext[] = "This is a secret message.";
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];

    const int HEX_KEY_SIZE = KEY_SIZE * 2 + 1; // 2 chars per byte + null terminator
    const int HEX_IV_SIZE = IV_SIZE * 2 + 1;  // 2 chars per byte + null terminator
    
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];


    generate_symmetric_key(key, KEY_SIZE);
    generate_symmetric_key(iv, IV_SIZE);
    
    unsigned char receive_key[KEY_SIZE];
    unsigned char receive_iv[IV_SIZE];
    unsigned char receive_port[6];
    
    char hex_key[HEX_KEY_SIZE];
    char hex_iv[HEX_IV_SIZE];

    // Convert key and IV to hex
    bin_to_hex(key, KEY_SIZE, hex_key);
    bin_to_hex(iv, IV_SIZE, hex_iv);


    // Format the message
    snprintf(msg, 1024, "k;%d;%s;%s;", 12341, hex_key, hex_iv);
    printf("msg: %s\n", msg);
    receive_key_iv(msg, receive_port, receive_key, KEY_SIZE, receive_iv, IV_SIZE);

    int ciphertext_len = aes_encrypt(plaintext, strlen((char*)plaintext), key, iv, ciphertext);
    if (ciphertext_len == -1) {
        std::cerr << "Encryption failed." << std::endl;
        return EXIT_FAILURE;
    }

    int decryptedtext_len = aes_decrypt(ciphertext, ciphertext_len, receive_key, receive_iv, decryptedtext);
    if (decryptedtext_len == -1) {
        std::cerr << "Decryption failed." << std::endl;
        return EXIT_FAILURE;
    }
    decryptedtext[decryptedtext_len] = '\0'; // Null-terminate the decrypted text
    std::cout << "Decrypted text is: " << decryptedtext << std::endl;
    
    return 0;

}
