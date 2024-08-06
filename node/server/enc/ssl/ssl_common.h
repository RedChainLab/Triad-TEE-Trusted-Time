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
#include <csignal>
#include <openssl/evp.h>

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "sgx_trts.h"
#include <cstdlib>

#include "../../../common/common.h"
#include "../../../common/openssl_utility.h"
#include <stdio.h>

#include <sgx_trts_exception.h>
#include "sgx_urts.h"

#include "sgx_tseal.h"
#include <sgx_trts_aex.h>


#include "../../../common/parsing/parsing.h"


#include "../tls_server_t.h"

#define ERROR_RETURN -1
#define SUCCESS_RETURN 0
#define CALIBRATION 10
#define TIMESTAMP 5

#define PORT 20


#define NOT_DELAYED 10
#define DELAYED 11
#define CALIBRATION_COLD_START 12
#define WAIT 0


#define NB_NODE 2
#define NB_CLIENT 1
#define NB_SERVER 1

#define NB_TOTAL (NB_NODE + NB_CLIENT + NB_SERVER)

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
    long long count;
    int index;
    int isAsking;
    long long timestamps;
    long long nb_aex;
    int isCalibrating;
    int isCounting;
    int canSend;
    int shouldSend;
    long long epoch;
    int dest[NB_TOTAL];
    //int already_asked[NB_NODE];
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

int bin_to_hex(const unsigned char* bin, int bin_len, char* hex);
int hex_to_bin(const char* hex, unsigned char* bin, int bin_len);

int send_key_iv(SSL* ssl, const unsigned char* key, int key_len, const unsigned char* iv, int iv_len);
bool receive_key_iv(char* msg, unsigned char* key, int key_len, unsigned char* iv, int iv_len);
void close_ssl_connection(node_connection &client);

void send_udp_packet(node_connection& nc, const unsigned char* message, int message_len);
int receive_udp_packet(node_connection& nc, long long* ts, int* already_sent, long long* epoch);

int exchange_key(node_connection& nc);
void generate_symmetric_key(unsigned char* key, int size);
int verify_callback(int preverify_ok, X509_STORE_CTX* ctx);
int in_array(int arr[], int val);
int parseMessage(const char* message, long long* ts, int* fields, int* nb_fields);

int compareArray(int* arr1, int* arr2, int nb_avaible_nodes);
#endif // COMMON_H