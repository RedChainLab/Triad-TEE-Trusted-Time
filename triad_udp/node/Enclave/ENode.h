/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>

#include "sodium.h"
#include <sgx_thread.h>
#include <vector>
#include <string>

#if defined(__cplusplus)
extern "C" {
#endif

int printf(const char *fmt, ...);

#if defined(__cplusplus)
}
#endif

#define SIZE 1024

enum {
    SUCCESS = 0,
    SOCKET_ALREADY_EXISTS = -1,
    SOCKET_CREATION_ERROR = -2,
    SOCKET_BINDING_ERROR = -3,
    READING_ERROR = -4,
    DECRYPTION_FAILED = -5,
    SENDING_ERROR = -6,
    SOCKET_INEXISTENT = -7
}; 

typedef struct {
    sgx_thread_rwlock_t stop_rwlock;
    bool* stop;
    int port;
    long long int* add_count;
    long long int* aex_count;
    long long int* monitor_aex_count;

    long long int* count_aex;
    long long int* monitor_aex;
}aex_handler_args_t;

class ENode
{
public:
    int port;
    bool stop;

    long long int add_count;
    long long int tsc;

    long long int aex_count;
    long long int monitor_aex_count;

    long long int count_aex[SIZE];
    long long int monitor_aex[SIZE];

    sgx_thread_rwlock_t stop_rwlock;
    sgx_thread_rwlock_t socket_rwlock;

    aex_handler_args_t aex_args;

    void test();
    int add_sibling(std::string hostname, uint16_t port);

    ENode(int _port);
    ~ENode();
private:
    int sock;

    unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
    unsigned char key[crypto_aead_aes256gcm_KEYBYTES];

    std::vector<std::pair<std::string, uint16_t>> siblings;

    bool isCounting;

    int setup_socket();
    int test_pong_ping();

    void countAdd();
    void loopOReadTSC();
    void loopEReadTSC();

    void monitor(int sleep_time, int sleep_inside_enclave, int verbosity);

    int handle_message(char* buff, char* ip, uint16_t port);
    int loop_recvfrom();

    void incrementNonce();
    int encrypt(const unsigned char* plaintext, const unsigned long long plen, unsigned char* ciphertext, unsigned long long* clen);
    int decrypt(const unsigned char* ciphertext, const unsigned long long clen, unsigned char* decrypted, unsigned long long* dlen);
    int test_encdec();

    bool should_stop();
    void eprintf(const char *fmt, ...);
    void print_siblings();
};

#endif /* !_ENCLAVE_H_ */
