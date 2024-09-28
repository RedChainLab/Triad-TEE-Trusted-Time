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
    SENDING_ERROR = -6,
    SOCKET_INEXISTENT = -7
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
    sgx_thread_rwlock_init(&stop_rwlock, NULL);
    sgx_thread_rwlock_init(&socket_rwlock, NULL);
    setup_socket();
    test_encdec();
}

ENode::~ENode()
{
    eprintf("Destroying node instance...\r\n");
    print_siblings();
    sgx_thread_rwlock_wrlock(&stop_rwlock);
    stop=true;
    sgx_thread_rwlock_unlock(&stop_rwlock);
    sgx_thread_rwlock_destroy(&stop_rwlock);
    sgx_thread_rwlock_wrlock(&socket_rwlock);
    close(sock);
    sgx_thread_rwlock_unlock(&socket_rwlock);
    sgx_thread_rwlock_destroy(&socket_rwlock);
    eprintf("Node instance destroyed.\r\n");
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
    sgx_thread_rwlock_rdlock(&stop_rwlock);
    bool retval = stop;
    sgx_thread_rwlock_unlock(&stop_rwlock);
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
        //eprintf("encl_recvfrom: %d, %p, %d, %d, %p, %p\r\n", sock, buff, sizeof(buff), 0, (struct sockaddr*)&cliAddr, &cliAddrLen);
        sgx_thread_rwlock_rdlock(&socket_rwlock);
        if(sock < 0)
        {
            sgx_thread_rwlock_unlock(&socket_rwlock);
            return SOCKET_INEXISTENT;
        }
        ssize_t readStatus = recvfrom(sock, buff, sizeof(buff), 0, ip, INET_ADDRSTRLEN, &cport);
        sgx_thread_rwlock_unlock(&socket_rwlock);
        if (readStatus < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                //eprintf("waiting for data...: %d\r\n", errno);
                continue;
            } else {
                eprintf("reading error...: %d\r\n", errno);
                close(sock);
                return READING_ERROR;
            }
        }
        else if(readStatus > 0)
        {
            //eprintf("encl_recvfrom: %d, %p, %d, %d, %s, %d\r\n", sock, buff, sizeof(buff), 0, ip, cport);
            eprintf("Message received from %s:%d: %s\r\n", ip, cport, buff);
            retval=handle_message(buff, ip, cport);
        }
    }
    return retval;
}

int ENode::handle_message(char* buff, char* ip, uint16_t cport)
{
    if(strcmp(buff, "Sibling")==0)
    {
        eprintf("Sibling message received from %s:%d\r\n", ip, cport);
        if(std::find(siblings.begin(), siblings.end(), std::make_pair(std::string(ip), cport)) == siblings.end())
        {
            siblings.emplace_back(ip, cport);
        }
        else
        {
            eprintf("Sibling already added.\r\n");
        }
    }
    else
    {
        sgx_thread_rwlock_rdlock(&socket_rwlock);
        if(sock < 0)
        {
            sgx_thread_rwlock_unlock(&socket_rwlock);
            return SOCKET_INEXISTENT;
        }
        ssize_t sendStatus = sendto(sock, buff, sizeof(buff), 0, ip, INET_ADDRSTRLEN, cport);
        sgx_thread_rwlock_unlock(&socket_rwlock);
        if (sendStatus < 0) {
            eprintf("sending error...: %d\r\n", errno);
            sgx_thread_rwlock_rdlock(&socket_rwlock);
            close(sock);
            sgx_thread_rwlock_unlock(&socket_rwlock);
            return SENDING_ERROR;
        }
    }
    return SUCCESS;
}

int ENode::setup_socket()
{
    sgx_thread_rwlock_wrlock(&socket_rwlock);
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

    struct timeval read_timeout;
    read_timeout.tv_sec = 0;
    read_timeout.tv_usec = 100;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));
    sgx_thread_rwlock_unlock(&socket_rwlock);
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

int ecall_init(uint16_t _port)
{
    printf("%sInitializing enclave...\r\n", ENCLAVE_MGR);
    if(nodes.find(_port) != nodes.end())
    {
        printf("%sNode already exists.\r\n", ENCLAVE_MGR);
        return SOCKET_ALREADY_EXISTS;
    }
    nodes.emplace(_port, new ENode(_port));
    return SUCCESS;
}

int ecall_stop(uint16_t _port)
{
    printf("%sStopping enclave...\r\n", ENCLAVE_MGR);
    if(nodes.find(_port) == nodes.end())
    {
        printf("%sNode does not exist.\r\n", ENCLAVE_MGR);
        return SOCKET_ALREADY_EXISTS;
    }
    delete nodes[_port];
    nodes.erase(_port);
    printf("%sEnclave stopped.\r\n", ENCLAVE_MGR);
    return SUCCESS;
}

int ecall_start(uint16_t _port)
{
    printf("%sStarting enclave logic...\r\n", ENCLAVE_MGR);
    if(nodes.find(_port) == nodes.end())
    {
        printf("%sNode does not exist...\r\n", ENCLAVE_MGR);
        return SOCKET_ALREADY_EXISTS;
    }
    nodes[_port]->test();
    printf("%sEnclave logic started.\r\n", ENCLAVE_MGR);
    return SUCCESS;
}

int ecall_add_sibling(uint16_t _port, const char* hostname, uint16_t port)
{
    printf("%sAdding sibling at %s:%d to node at %d...\r\n", ENCLAVE_MGR, hostname, port, _port);
    if(nodes.find(_port) == nodes.end())
    {
        printf("%sNode at %d does not exist...\r\n", ENCLAVE_MGR, _port);
        return SOCKET_ALREADY_EXISTS;
    }
    nodes[_port]->add_sibling(std::string(hostname), port);
    printf("%sSibling at %s:%d added to node at %d.\r\n", ENCLAVE_MGR, hostname, port, _port);
    return SUCCESS;
}

void ENode::test()
{
    loop_recvfrom();
}

int ENode::add_sibling(std::string hostname, uint16_t _port)
{
    eprintf("Adding sibling %s:%d to node...\r\n", hostname, _port);
    siblings.emplace_back(hostname, _port);

    const char* buff = "Sibling";
    //eprintf("sento: %d, %s, %d, %d, %s, %d\r\n", sock, buff, sizeof(buff), 0, hostname.c_str(), _port);
    ssize_t sendStatus = sendto(sock, buff, sizeof(buff), 0, hostname.c_str(), INET_ADDRSTRLEN, _port);
    if (sendStatus< 0) {
        eprintf("sending error...: %d\r\n", errno);
        sgx_thread_rwlock_wrlock(&socket_rwlock);
        close(sock);
        sgx_thread_rwlock_unlock(&socket_rwlock);
        return SENDING_ERROR;
    }
    return SUCCESS;
}

void ENode::print_siblings()
{
    eprintf("%d siblings: ", siblings.size());
    for(auto& sibling: siblings)
    {
        printf("%s:%d, ", sibling.first.c_str(), sibling.second);
    }
    printf("\r\n");
}