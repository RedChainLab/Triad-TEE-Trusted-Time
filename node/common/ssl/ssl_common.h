#ifndef COMMON2_H
#define COMMON2_H

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

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "sgx_trts.h"
#include <cstdlib>

#include "../common.h"
#include "../openssl_utility.h"
#include "tls_client_t.h"
#include <stdio.h>

#include <openssl/evp.h>


#include "../common.h"
#include "../openssl_utility.h"
#include "tls_client_t.h"
#define NB_NODE 2
#define KEY_SIZE 32 // 256 bits
#define IV_SIZE 16  // 128 bits
#define BUFSIZE 1024
#define MSG_SIZE 1024

#define MAX_SERVERS 3

typedef struct {
    int count;
    int isCounting;
    int calibrationStart;
    sgx_thread_cond_t startCounting;
    sgx_thread_cond_t startCalibration;
    sgx_thread_mutex_t mutex;

} cond_buffer_t;

typedef struct {
    SSL* ssl_session;
    int count;
    int isAsking;
    int isReading;
    int idFetching;
    int isVerifying;
    int runtimeStart;
    int pendingDemand;
    sgx_thread_cond_t startRuntime;
    sgx_thread_cond_t startAsking;
    sgx_thread_cond_t startReading;
    sgx_thread_cond_t startFetching;
    sgx_thread_cond_t startVerifying;
    sgx_thread_cond_t demandPending;
    sgx_thread_mutex_t mutex;

}cond_runtime_t;



typedef struct {
    int socket_fd;
    SSL *ssl_session;
    char *server_name;
    char *server_port;
} server_connection;




typedef struct {
    int socket_fd;
    SSL *ssl_session;
    const char *node_name;
    int node_port;

    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    int is_connected;
} node_connection;

unsigned long inet_addr2(const char *str);

int create_socket(const char* server_name,const char* server_port);
int create_listener_socket(int port, int& server_socket);


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
void set_up_udp_socket(const char* server_ip, int server_port, int& sockfd);
void receive_udp_packet(node_connection& nc, int& sockfd, unsigned char* key, unsigned char* iv);

int exchange_key(node_connection& nc);
void generate_symmetric_key(unsigned char* key, int size);
int verify_callback(int preverify_ok, X509_STORE_CTX* ctx);
#endif // COMMON_H