#ifndef SERVER_COMMON_H
#define SERVER_COMMON_H

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "sgx_trts.h"
#include <cstdlib>

#include "../common.h"
#include "../openssl_utility.h"
#include "tls_client_t.h"

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


unsigned long inet_addr2(const char *str);

int create_socket(const char* server_name,const char* server_port);
int create_listener_socket(int port, int& server_socket);

int verify_callback(int preverify_ok, X509_STORE_CTX* ctx);

//int launch_tls_client2(const char* server_name,const char* server_port, char* msg, long long* rsp);
//int communicate_with_server(SSL* ssl, char* msg, long long* rsp);

#endif // SERVER_COMMON_H