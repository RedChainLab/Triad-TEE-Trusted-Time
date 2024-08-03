#ifndef COMMON_H
#define COMMON_H

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
#include <csignal>
#include <openssl/evp.h>
#include <ctime>
#include <mutex>
#include <thread>
#include <chrono>

#define ERROR_RETURN -1
#define CALIBRATION 10

#define NOT_DELAYED 10
#define DELAYED 11
#define CALIBRATION_COLD_START 12
#define WAIT 0

#define TIMESTAMP 5

#define PORT 20

#define NB_NODE 3
#define NB_CLIENT 1
#define KEY_SIZE 32 // 256 bits
#define IV_SIZE 16  // 128 bits
#define BUFSIZE 1024
#define MSG_SIZE 1024
#define t_print printf

typedef struct {
    int socket_fd;
    SSL *ssl_session;
    const char *node_name;
    int node_port;

    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    int is_connected;
} node_connection;

typedef struct {
    std::mutex mtx;
    int destination[NB_NODE] = {-1, -1, -1};
    int waiting_time = 500;
    int misc = 0;
    int is_calibrating = 0;
}sync_struct;



int aes_decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext);
int aes_encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv, unsigned char* ciphertext);

int split(const std::string& message, unsigned char** cryptographic_key, unsigned char** port);
void bin_to_hex(const unsigned char* bin, int bin_len, char* hex);
void send_key_iv(SSL* ssl, const unsigned char* key, int key_len, const unsigned char* iv, int iv_len);
bool receive_key_iv(char* msg, unsigned char* key, int key_len, unsigned char* iv, int iv_len);
bool send_int(SSL* ssl, int value);
bool receive_int(SSL* ssl, int &value);
void close_ssl_connection(node_connection &client);

void send_udp_packet(node_connection& nc, const char* server_ip, int server_port, int& sockfd, const unsigned char* message, int message_len);
int receive_udp_packet(node_connection& nc, int& sockfd, unsigned char* key, unsigned char* iv, int* dest, int* misc, int* waiting_time);
void receive_udp_packet_temp(node_connection& nc, int& sockfd);

int exchange_key(node_connection& nc);
void generate_symmetric_key(unsigned char* key, int size);
unsigned long inet_addr2(const char *str);


long getUnixTime();
long long getHighPrecisionUnixTime();
int parseMessage(const char* message, int* fields, int* nb_fields);
#endif // COMMON_H