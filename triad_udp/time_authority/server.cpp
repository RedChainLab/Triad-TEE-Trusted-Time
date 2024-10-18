#include <iostream>
#include <thread>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sodium.h>
#include <mutex>

using namespace std;

#define PORT 12340
#define DRIFT_STR "Drift"

std::vector<std::thread> threads;
std::mutex sendMutex;

void handleMsg(int serSockDes, struct sockaddr_in cliAddr, socklen_t cliAddrLen, const char* buff, ssize_t readStatus, const unsigned char* nonce, const unsigned char* key) 
{
    printf("Handling message from %d\r\n", ntohs(cliAddr.sin_port));
    
    // Dynamic allocation for decrypted buffer
    unsigned char buff_dec[1024]; // Ensure this is large enough for your data
    unsigned long long buff_len_dec;
    
    if (crypto_aead_aes256gcm_decrypt(buff_dec, &buff_len_dec,
                                       NULL, (const unsigned char*)buff, readStatus,
                                       NULL, 0, nonce, key) != 0) {
        perror("Decryption failed\r\n");
        return;
    }

    const long long int recvd_calib_msg_count = *(const long long int*)((const char*)buff_dec + strlen(DRIFT_STR));
    const int sleep_time = *(const int*)((const char*)buff_dec + strlen(DRIFT_STR) + sizeof(recvd_calib_msg_count));

    cout.write((const char*)buff_dec, buff_len_dec);
    cout << endl;
    cout << "Received from " << ntohs(cliAddr.sin_port) << " calib_msg: " << recvd_calib_msg_count << " and will sleep for " << sleep_time << "ms" << endl;

    usleep(sleep_time * 1000);

    // Prepare for encryption
    unsigned char buff_enc[buff_len_dec + crypto_aead_aes256gcm_ABYTES];
    unsigned long long buff_len_enc;

    // Encrypt the response
    sendMutex.lock(); // Lock the mutex before sending
    if (crypto_aead_aes256gcm_encrypt(buff_enc, &buff_len_enc,
                                       buff_dec, buff_len_dec,
                                       NULL, 0, NULL, nonce, key) != 0) {
        perror("Encryption failed\r\n");
        sendMutex.unlock();
        return;
    }
    
    if (sendto(serSockDes, buff_enc, buff_len_enc, 0, (struct sockaddr*)&cliAddr, cliAddrLen) < 0) { 
        perror("sending error...\n");
    } else {
        cout << "Sent back to " << ntohs(cliAddr.sin_port) << endl;
    }
    sendMutex.unlock(); // Unlock the mutex after sending
}

int main() 
{
    int serSockDes;
    struct sockaddr_in serAddr, cliAddr;
    socklen_t cliAddrLen;
    char buff[1024];
    ssize_t readStatus;

    // Create socket
    serSockDes = socket(AF_INET, SOCK_DGRAM, 0);
    if (serSockDes < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    memset(&serAddr, 0, sizeof(serAddr));
    serAddr.sin_family = AF_INET;
    serAddr.sin_addr.s_addr = INADDR_ANY;
    serAddr.sin_port = htons(PORT);

    // Bind socket
    if (bind(serSockDes, (const struct sockaddr *)&serAddr, sizeof(serAddr)) < 0) {
        perror("bind failed");
        close(serSockDes);
        exit(EXIT_FAILURE);
    }

    unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
    memset(nonce, 0, sizeof(nonce));

    unsigned char key[crypto_aead_aes256gcm_KEYBYTES];
    const char* test_key = "b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4";
    sodium_hex2bin(key, crypto_aead_aes256gcm_KEYBYTES,
                   test_key, strlen(test_key),
                   NULL, NULL, NULL);

    while (true) {
        cliAddrLen = sizeof(cliAddr);
        readStatus = recvfrom(serSockDes, buff, sizeof(buff), 0, (struct sockaddr*)&cliAddr, &cliAddrLen);
        if (readStatus < 0) {
            perror("reading error...\n");
            close(serSockDes);
            exit(-1);
        }

        // Pass only the read data to the thread
        cout << "Received " << readStatus << " from " << ntohs(cliAddr.sin_port) << endl;
        threads.push_back(std::thread(handleMsg, serSockDes, cliAddr, cliAddrLen, buff, readStatus, nonce, key));
    }

    for (auto& th : threads) th.join();
    close(serSockDes);
    return 0;
}
