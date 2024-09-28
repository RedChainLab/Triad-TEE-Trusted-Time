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
#include "ENode.h"
#include <stdio.h>
#include <sgx_trts_aex.h>
#include <sgx_thread.h>
#include <map>

#ifdef __cplusplus
extern "C" {
#endif

int printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, BUFSIZ, fmt, args);
    va_end(args);
    ocall_print_string(buf);
    return 0;
}

#ifdef __cplusplus
}
#endif

typedef enum {
    SYSCALL_SLEEP = 0,
    O_READTSC_SLEEP = 1,
    E_READTSC_SLEEP = 2,
    C_ADDER_SLEEP = 3,
    ASM_ADDER_SLEEP = 4,
    SELF_MONITOR = 5,
    AEX_SELF_MONITOR = 6,
    AEX_ASM_SELF_MONITOR = 7
}sleep_type_t;

std::map<int /*port*/, ENode*> nodes;

static void printArray(long long int *arr, long long int size, long long int reference){
    /*
    Print a array of size SIZE, which contains the number of ADD operations performed before each AEX occurs.
    */
    for(int i = 0; i < size ; i++){
        printf("%d;%lld\n", i, arr[i]-reference);
    }
}

inline void log_aex(long long int* arr, long long int& next_index, long long int* add_count){
    if(next_index < SIZE)
    {
        arr[next_index++] = *add_count;
    }
    else
    {
        printf("Error: Array is full\n");
    }
}

static void counter_aex_handler(const sgx_exception_info_t *info, const void * args)
{
    /*
    a custom handler that will be called when an AEX occurs, storing the number of ADD operations (performed in another thread) in a global array. This allows you to 
    know when AEX occurs (the number of ADD operations increases linearly) and how often it occurs.
    */
    (void)info;
    aex_handler_args_t* aex_args;
    memcpy(&aex_args, args, sizeof(aex_handler_args_t*));
    printf("AEX %d %d\r\n", aex_args->port, *aex_args->stop);
    log_aex(aex_args->count_aex, *(aex_args->aex_count), aex_args->add_count);
}

static void monitor_aex_handler(const sgx_exception_info_t *info, const void * args)
{
    /*
    a custom handler that will be called when an AEX occurs, storing the number of ADD operations (performed in another thread) in a global array. This allows you to 
    know when AEX occurs (the number of ADD operations increases linearly) and how often it occurs.
    */
    (void)info;
    aex_handler_args_t* aex_args;
    memcpy(&aex_args, args, sizeof(aex_handler_args_t*));
    printf("AEX %d %d\r\n", aex_args->port, *aex_args->stop);
    log_aex(aex_args->monitor_aex, *(aex_args->monitor_aex_count), aex_args->add_count);
}

inline long long int rdtsc(void){
    /*
    Read the TSC register
    */
    unsigned int lo, hi;
    __asm__ __volatile__("rdtscp" : "=a" (lo), "=d" (hi));
    //t_print("lo: %d, hi: %d\n", lo, hi);
    return ((uint64_t)hi << 32) | lo;
}

void ENode::countAdd(void){
    /*
    The function that will be called in another thread to perform ADD operations.
    */
    //see_pid("countADD");
    const char* args = NULL; 
    sgx_aex_mitigation_node_t node;
    sgx_register_aex_handler(&node, counter_aex_handler, (const void*)args);
    while (this->isCounting);
    while(this->isCounting == 1){
        add_count++; 
    }
    sgx_unregister_aex_handler(counter_aex_handler);
}

void ENode::loopOReadTSC(void){
    /*
    The function that will be called in another thread to perform ADD operations.
    */
    //see_pid("countTSC");
    const char* args = NULL; 
    sgx_aex_mitigation_node_t node;
    sgx_register_aex_handler(&node, counter_aex_handler, (const void*)args);
    while (this->isCounting);
    while(this->isCounting){
        ocall_readTSC(&add_count);
    }
    sgx_unregister_aex_handler(counter_aex_handler);
}

void ENode::loopEReadTSC(void){
    /*
    The function that will be called in another thread to perform ADD operations.
    */
    //see_pid("countTSC");
    const char* args = NULL; 
    sgx_aex_mitigation_node_t node;
    sgx_register_aex_handler(&node, counter_aex_handler, (const void*)args);
    while (this->isCounting);
    while(this->isCounting){
        add_count = rdtsc();
    }
    sgx_unregister_aex_handler(counter_aex_handler);
}

ENode::ENode(int _port):port(_port), stop(false), add_count(0), aex_count(0), monitor_aex_count(0), sock(-1), isCounting(false), monitor_stopped(false)
{
    eprintf("Creating ENode instance...\r\n");
    memset(count_aex, 0, sizeof(count_aex));
    memset(monitor_aex, 0, sizeof(monitor_aex));

    aex_args.stop = &stop;
    aex_args.port = port;
    aex_args.add_count = &add_count;

    sgx_thread_rwlock_init(&stop_rwlock, NULL);
    sgx_thread_rwlock_init(&socket_rwlock, NULL);
    setup_socket();
    test_encdec();
    eprintf("ENode instance created.\r\n");
}

ENode::~ENode()
{
    eprintf("Destroying ENode instance...\r\n");
    print_siblings();
    sgx_thread_rwlock_wrlock(&stop_rwlock);
    stop=true;
    sgx_thread_rwlock_unlock(&stop_rwlock);
    while(!monitor_stopped);
    sgx_thread_rwlock_destroy(&stop_rwlock);
    eprintf("ENode instance stopping...\r\n");
    sgx_thread_rwlock_wrlock(&socket_rwlock);
    close(sock);
    sgx_thread_rwlock_unlock(&socket_rwlock);
    sgx_thread_rwlock_destroy(&socket_rwlock);
    eprintf("ENode instance destroyed.\r\n");
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

bool ENode::should_stop()
{
    sgx_thread_rwlock_rdlock(&stop_rwlock);
    bool retval = stop;
    sgx_thread_rwlock_unlock(&stop_rwlock);
    return retval;
}

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
        for(unsigned int i = 0; i < crypto_aead_aes256gcm_NPUBBYTES; i++)
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

    crypto_aead_aes256gcm_encrypt(ciphertext, clen,
                                  plaintext, plen,
                                  NULL, 0, NULL, nonce, key);
    
    return SUCCESS;
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
    serAddr.sin_port = htons((int16_t)port);
    serAddr.sin_addr.s_addr = INADDR_ANY;

    if ((bind(this->sock, (struct sockaddr*)&serAddr, sizeof(serAddr))) < 0) {
        eprintf("server socket binding error...: %d\r\n", errno);
        close(this->sock);
        return SOCKET_BINDING_ERROR;
    }

    struct timeval read_timeout;
    read_timeout.tv_sec = 0;
    read_timeout.tv_usec = 200000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));
    sgx_thread_rwlock_unlock(&socket_rwlock);
    eprintf("server socket created...: %d\r\n", this->sock);
    return SUCCESS;
}

int ENode::loop_recvfrom()
{
    int retval=SUCCESS;
    while (retval == SUCCESS && !should_stop())
    {    
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
            retval=handle_message(buff, ip, (uint16_t)cport);
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
            eprintf("Sibling added.\r\n");
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

void ENode::print_siblings()
{
    eprintf("%d siblings: ", siblings.size());
    for(auto& sibling: siblings)
    {
        printf("%s:%d, ", sibling.first.c_str(), sibling.second);
    }
    printf("\r\n");
}

void ENode::monitor(int sleep_time, int sleep_inside_enclave, int verbosity){
    /*
    the main thread that will be called by the application.
    */ 
    sgx_aex_mitigation_node_t node;
    if(sleep_inside_enclave != SELF_MONITOR){
        if(sleep_inside_enclave == AEX_SELF_MONITOR || sleep_inside_enclave == AEX_ASM_SELF_MONITOR){
            sgx_register_aex_handler(&node, counter_aex_handler, (const void*)&aex_args);
        }
        else{
            sgx_register_aex_handler(&node, monitor_aex_handler, (const void*)&aex_args);
        }
    }
    long long int reference = 0;
    while (!should_stop())
    {    
        reference = 0;
        this->isCounting = true;
        switch(sleep_inside_enclave){
            case SYSCALL_SLEEP:

                ocall_sleep(&sleep_time);
            break;
            case O_READTSC_SLEEP:
            {

                ocall_readTSC(&reference);
                while(tsc-reference < 3000000000*sleep_time){
                    ocall_readTSC(&tsc);
                }
            }
            break;
            case E_READTSC_SLEEP:
            {

                reference = rdtsc();
                while(tsc-reference < 3000000000*sleep_time){
                    tsc = rdtsc();
                }
            }
            break;
            case C_ADDER_SLEEP:
            {

                for( long long int counter = 0; counter < 529*sleep_time; counter++){
                    for(int i = 0; i < 1000000; i++);
                }
            }
            break;
            case ASM_ADDER_SLEEP:
            {

                long long int counter = 3000000*sleep_time;
                __asm__ volatile(
                    "mov %0, %%rcx\n\t"
                    "mov %1, %%rax\n\t"
                    "1: dec %%rax\n\t"
                    "mov %%rax, (%%rcx)\n\t"
                    "test %%rax, %%rax\n\t"
                    "jnz 1b"
                    :
                    : "r"(&counter), "r"(counter)
                    : "rcx", "rax"
                );
                //log_aex(count_aex, aex_count);
            }
            break;
            case SELF_MONITOR:
            {
                long long int delta=0;
                long long int THRESHOLD=600;
                reference=rdtsc();
                do{
                    long long int a=rdtsc();
                    do{
                        add_count=rdtsc();
                        delta=add_count-a;
                        a=add_count;
                    } while(add_count-reference<3000000000*sleep_time && delta<THRESHOLD && delta>0);
                    if(delta>=THRESHOLD){
                        log_aex(monitor_aex, monitor_aex_count, &add_count);
                    }
                    else if(delta<0){
                        eprintf("Error: non-increasing TSC! delta=%lld\n", delta);
                        break;
                    }
                } while(add_count-reference<3000000000*sleep_time);
            }
            break;
            case AEX_SELF_MONITOR:
            {
                reference=0;
                long long int start_tsc=rdtsc();
                long long int stop_tsc=3000000*sleep_time+start_tsc;
                long long int current_tsc=reference;
                do{
                    add_count++;
                    current_tsc=rdtsc();
                } while(current_tsc<stop_tsc);
            }
            break;
            case AEX_ASM_SELF_MONITOR:
            {
                reference=0;
                long long int start_tsc=rdtsc();
                long long int stop_tsc=3000000*sleep_time+start_tsc;
                asm volatile(
                    "movq %0, %%r8\n\t"
                    "movq %1, %%r9\n\t"
                    "movq $0, %%r10\n\t"

                    "1: rdtsc\n\t"
                    "shlq $32, %%rdx\n\t"
                    "orq %%rax, %%rdx\n\t"
                    "incq %%r10\n\t"
                    "movq %%r10, (%%r8)\n\t"
                    "cmpq %%r9, %%rdx\n\t"
                    "jl 1b\n\t"
                    :
                    : "r"(&add_count), "r"(stop_tsc)
                    : "rax", "rdx", "r8", "r9"
                );
            }
            break;
        }
        this->isCounting = false;

        if(verbosity>=1)
        {
            printf("idx;count\n");
            printArray(count_aex, aex_count, reference);
        }
        if(verbosity>=2)
        {
            printf("idx;monitor_aex_count\n");
            printArray(monitor_aex, monitor_aex_count, reference);
        }
        if(verbosity==1)
        {
            printf("%lld;%lld\n", aex_count, add_count-reference);
        }
        if(verbosity>=2)
        {
            printf("counter_aex_count;monitor_aex_count;final_count\n");
            printf("%lld;%lld;%lld\n", aex_count, monitor_aex_count, add_count-reference);
        }
    }
    if(sleep_inside_enclave != SELF_MONITOR){
        if(sleep_inside_enclave == AEX_SELF_MONITOR || sleep_inside_enclave == AEX_ASM_SELF_MONITOR){
            sgx_unregister_aex_handler(counter_aex_handler);
        }
        else{
            sgx_unregister_aex_handler(monitor_aex_handler);
        }
    }
    eprintf("Monitoring done.\r\n");
    monitor_stopped = true;
}

int ENode::add_sibling(std::string hostname, uint16_t _port)
{
    eprintf("Adding sibling %s:%d to node...\r\n", hostname, _port);
    if(std::find(siblings.begin(), siblings.end(), std::make_pair(hostname, _port)) != siblings.end())
    {
        eprintf("Sibling already added.\r\n");
        return SUCCESS;
    }
    siblings.emplace_back(hostname, _port);
    eprintf("Sibling added.\r\n");
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
