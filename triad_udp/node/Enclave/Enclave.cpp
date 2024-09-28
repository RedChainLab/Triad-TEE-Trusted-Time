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
#include "sys/socket.h"
#include "Enclave_t.h"
#include "Enclave.h"
#include <stdio.h>
#include <string>
#include <sgx_trts_aex.h>
#include <sgx_thread.h>
#include <map>

#ifdef __cplusplus
extern "C" {
#endif

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, BUFSIZ, fmt, args);
    va_end(args);
    ocall_print_string(buf);
}

#ifdef __cplusplus
}
#endif

#define ENCLAVE_MGR "[ENode Mgr]> "

enum {
    SUCCESS = 0,
    SOCKET_ALREADY_EXISTS = -1,
    SOCKET_CREATION_ERROR = -2,
    SOCKET_BINDING_ERROR = -3,
    READING_ERROR = -4,
    DECRYPTION_FAILED = -5,
    SENDING_ERROR = -6
}; 

std::map<int /*port*/, ENode*> nodes;

void ENode::incrementNonce(void)
{
    static bool init = false;
    if(!init)
    {
        memset(nonce, 0, sizeof(nonce));
        init = true;
    }
    else
    {
        for(int i = 0; i < crypto_aead_aes256gcm_NPUBBYTES; i++)
        {
            nonce[i]++;
            if(nonce[i] != 0)
            {
                break;
            }
        }
    }
}

int ENode::encrypt(const unsigned char* plaintext, const unsigned long long plen, unsigned char* ciphertext, unsigned long long* clen)
{
    incrementNonce();
    randombytes_buf(key, sizeof(key));

    crypto_aead_aes256gcm_encrypt((unsigned char*)ciphertext, clen,
                                  (unsigned char*)plaintext, plen,
                                  NULL, 0, NULL, nonce, key);
}

int ENode::decrypt(const unsigned char* ciphertext, const unsigned long long clen, unsigned char* decrypted, unsigned long long* dlen)
{
    if (crypto_aead_aes256gcm_decrypt(decrypted, dlen,
                                      NULL, ciphertext, clen,
                                      NULL, 0, nonce, key) != 0) {
        eprintf("Decryption failed\r\n");
        return -1;
    }
    return 0;
}

int ENode::test_encdec()
{
    unsigned char msg[] = "Hello!";
    unsigned long long msg_len = sizeof(msg);
    unsigned char ciphertext[sizeof(msg) + crypto_aead_aes256gcm_ABYTES];
    unsigned long long ciphertext_len = sizeof(ciphertext);
    unsigned char decrypted[sizeof(msg)];
    unsigned long long decrypted_len = sizeof(decrypted);
    eprintf("Message: %s\r\n", msg);
    encrypt(msg, msg_len, ciphertext, &ciphertext_len);
    eprintf("Encrypted: %s\r\n", ciphertext);
    if(decrypt(ciphertext, ciphertext_len, decrypted, &decrypted_len))
    {
        return DECRYPTION_FAILED;
    }
    eprintf("Decrypted: %s\r\n", decrypted);
    return SUCCESS;
}

ENode::ENode(int _port):port(_port), stop(false)
{
    sgx_thread_rwlock_init(&mutex, NULL);
    setup_socket();
    test_encdec();
}

ENode::~ENode()
{
    eprintf("Destroying node instance...\r\n");
    sgx_thread_rwlock_wrlock(&mutex);
    stop=true;
    sgx_thread_rwlock_unlock(&mutex);
    sgx_thread_rwlock_destroy(&mutex);
    close(sock);
    eprintf("Node instance destroyed...\r\n");
}

int ENode::test_pong_ping()
{
    struct sockaddr_in cliAddr;
    memset(&cliAddr, 0, sizeof(cliAddr)); // Clear the structure
    socklen_t cliAddrLen = sizeof(cliAddr);
    char buff[1024] = {0};
    char ip[INET_ADDRSTRLEN];
    int cport;
    eprintf("encl_recvfrom: %d, %p, %d, %d, %p, %p\r\n", sock, buff, sizeof(buff), 0, (struct sockaddr*)&cliAddr, &cliAddrLen);
    ssize_t readStatus = recvfrom(sock, buff, sizeof(buff), 0, ip, INET_ADDRSTRLEN, &cport);
    eprintf("encl_recvfrom: %d, %p, %d, %d, %s, %d\r\n", sock, buff, sizeof(buff), 0, ip, INET_ADDRSTRLEN, cport);
    if (readStatus < 0) {
        eprintf("reading error...: %d\r\n", errno);
        close(sock);
        return READING_ERROR;
    } else {
        eprintf("Message received from %s:%d: %s\r\n", ip, cport, buff);
    }

    if (sendto(sock, buff, sizeof(buff), 0, ip, INET_ADDRSTRLEN, cport) < 0) {
        eprintf("sending error...: %d\r\n", errno);
        close(sock);
        return SENDING_ERROR;
    }
    return SUCCESS;
}

bool ENode::should_stop()
{
    sgx_thread_rwlock_rdlock(&mutex);
    bool retval = stop;
    sgx_thread_rwlock_unlock(&mutex);
    return retval;
}

int ENode::loop_recvfrom()
{
    int retval=SUCCESS;
    while (retval == SUCCESS && !should_stop())
    {    
        struct sockaddr_in cliAddr;
        memset(&cliAddr, 0, sizeof(cliAddr)); // Clear the structure
        socklen_t cliAddrLen = sizeof(cliAddr);
        char buff[1024] = {0};
        char ip[INET_ADDRSTRLEN];
        int cport;
        eprintf("encl_recvfrom: %d, %p, %d, %d, %p, %p\r\n", sock, buff, sizeof(buff), 0, (struct sockaddr*)&cliAddr, &cliAddrLen);
        ssize_t readStatus = recvfrom(sock, buff, sizeof(buff), 0, ip, INET_ADDRSTRLEN, &cport);
        eprintf("encl_recvfrom: %d, %p, %d, %d, %s, %d\r\n", sock, buff, sizeof(buff), 0, ip, INET_ADDRSTRLEN, port);
        if (readStatus < 0) {
            eprintf("reading error...: %d\r\n", errno);
            close(sock);
            return READING_ERROR;
        }
        eprintf("Message received from %s:%d: %s\r\n", ip, cport, buff);
        retval=handle_message(buff, ip, cport);
    }
    return retval;
}

int ENode::handle_message(char* buff, char* ip, int cport)
{
    if (sendto(sock, buff, sizeof(buff), 0, ip, INET_ADDRSTRLEN, cport) < 0) {
        eprintf("sending error...: %d\r\n", errno);
        close(sock);
        return SENDING_ERROR;
    }
    return SUCCESS;
}

int ENode::setup_socket()
{
    //creating a new server socket
    if ((this->sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        eprintf("server socket creation error...\r\n");
        return SOCKET_CREATION_ERROR;
    }

    //binding the port to ip and port
    struct sockaddr_in serAddr;
    serAddr.sin_family = AF_INET;
    serAddr.sin_port = htons(port);
    serAddr.sin_addr.s_addr = INADDR_ANY;

    if ((bind(this->sock, (struct sockaddr*)&serAddr, sizeof(serAddr))) < 0) {
        eprintf("server socket binding error...: %d\r\n", errno);
        close(this->sock);
        return SOCKET_BINDING_ERROR;
    }
    eprintf("server socket created...: %d\r\n", this->sock);
    return SUCCESS;
}

void ENode::eprintf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    std::string str = std::string("[ENode ") + std::to_string(port) + "]> ";
    str += fmt;
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, BUFSIZ, str.c_str(), args);
    va_end(args);
    ocall_print_string(buf);
}

int ecall_init(int _port)
{
    printf("%sInitializing enclave...\r\n", ENCLAVE_MGR);
    if(nodes.find(_port) != nodes.end())
    {
        printf("%sNode already exists...\r\n", ENCLAVE_MGR);
        return SOCKET_ALREADY_EXISTS;
    }
    nodes.emplace(_port, new ENode(_port));
    return SUCCESS;
}

int ecall_stop(int _port)
{
    printf("%sStopping enclave...\r\n", ENCLAVE_MGR);
    if(nodes.find(_port) == nodes.end())
    {
        printf("%sNode does not exist...\r\n", ENCLAVE_MGR);
        return SOCKET_ALREADY_EXISTS;
    }
    delete nodes[_port];
    nodes.erase(_port);
    return SUCCESS;
}

int ecall_start(int _port)
{
    if(nodes.find(_port) == nodes.end())
    {
        printf("%sNode does not exist...\r\n", ENCLAVE_MGR);
        return SOCKET_ALREADY_EXISTS;
    }
    printf("%sStarting enclave logic...\r\n", ENCLAVE_MGR);
    nodes[_port]->test();
    return SUCCESS;
}

void ENode::test()
{
    loop_recvfrom();
}