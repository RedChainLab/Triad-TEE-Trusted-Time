#ifndef SSL_SERVER_H
#define SSL_SERVER_H

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "../../common/openssl_utility.h"
#include <sgx_trts_exception.h>
#include "sgx_urts.h"
#include "sgx_trts.h"
#include <cstdlib>
#include "sgx_tseal.h"
#include "tls_server_t.h"
#include <sgx_trts_aex.h>
#include <sgx_trts_exception.h>
#include <atomic>
#include <future>
#include "ssl_common.h"
#include "../../../common/parsing/parsing.h"


int communicate_with_trusted_server(SSL* ssl, int& i, uint64_t& mean_tsc_0, uint64_t& mean_tsc_500, uint32_t& count, cond_buffer_t* b, int waiting_time);
int launch_tls_client_with_trusted_server(const char* server_name,const char* server_port, int& i, uint32_t& count,
    uint64_t& mean_tsc_0, uint64_t& mean_tsc_500, cond_buffer_t *b, int waiting_time);
int handle_communication_until_done(int& server_socket_fd, int& client_socket_fd, SSL_CTX*& ssl_server_ctx, SSL*& ssl_session, bool keep_server_up);
int launch_tls_client2(const char* server_name,const char* server_port,const char* msg, long long* rsp);
int communicate_with_server(SSL* ssl, char* msg, long long* rsp);

#endif // SSL_SERVER_H