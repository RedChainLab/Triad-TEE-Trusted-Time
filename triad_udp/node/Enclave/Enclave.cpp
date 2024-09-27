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
#include "sodium.h"
#include "sys/socket.h"
#include "Enclave_t.h"
#include <stdio.h>
#include <string>
#include <sgx_trts_aex.h>
#include <sgx_thread.h>

unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
unsigned char key[crypto_aead_aes256gcm_KEYBYTES];

#ifdef __cplusplus
extern "C" {
#endif

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

#ifdef __cplusplus
}
#endif

void incrementNonce(void)
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

int encrypt(unsigned char* plaintext, unsigned long long plen, unsigned char* ciphertext, unsigned long long clen)
{
    unsigned long long decrypted_len;
    unsigned char decrypted[plen + 1];

    incrementNonce();
    randombytes_buf(key, sizeof(key));

    crypto_aead_aes256gcm_encrypt((unsigned char*)ciphertext, &clen,
                                  (unsigned char*)plaintext, plen,
                                  NULL, 0, NULL, nonce, key);
}

int decrypt(unsigned char* ciphertext, unsigned long long clen, unsigned char* decrypted, unsigned long long dlen)
{
    unsigned long long decrypted_len;
    if (crypto_aead_aes256gcm_decrypt(decrypted, &decrypted_len,
                                      NULL, ciphertext, clen,
                                      NULL, 0, nonce, key) != 0) {
        printf("Decryption failed\r\n");
        return -1;
    }
    return 0;
}

void sendMessage()
{
    int sock;
    //creating a new server socket
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("server socket creation error...\r\n");
    }

    //binding the port to ip and port
    struct sockaddr_in serAddr;
    serAddr.sin_family = AF_INET;
    serAddr.sin_port = htons(12348);
    serAddr.sin_addr.s_addr = INADDR_ANY;

    if ((bind(sock, (struct sockaddr*)&serAddr, sizeof(serAddr))) < 0) {
        printf("server socket binding error...: %d\r\n", errno);
        close(sock);
    }
    printf("server socket created...: %d\r\n", sock);

    struct sockaddr_in cliAddr;
    memset(&cliAddr, 0, sizeof(cliAddr)); // Clear the structure
    socklen_t cliAddrLen = sizeof(cliAddr);
    char buff[1024] = {0};
    printf("encl_recvfrom: %d, %p, %d, %d, %p, %p\r\n", sock, buff, sizeof(buff), 0, (struct sockaddr*)&cliAddr, &cliAddrLen);
    ssize_t readStatus = recvfrom(sock, buff, sizeof(buff), 0);
    if (readStatus < 0) {
        printf("reading error...: %d\r\n", errno);
        close(sock);
    } else {
        printf("Message received: %s\r\n", buff);
    }
}
