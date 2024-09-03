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
#include "Enclave_t.h"
#include <stdio.h>
#include <sgx_trts_aex.h>
#include <sgx_thread.h>
#define SIZE 65536

long long int add_count = 0;
long long int tsc = 0;

long long int aex_count = 0;
long long int monitor_aex_count = 0;

long long int count_aex[SIZE];
long long int monitor_aex[SIZE];

# define BUFSIZ  8192

typedef struct {
    int isCounting;
    int isWaiting;
    sgx_thread_cond_t startCounting;
    sgx_thread_mutex_t mutex;

}cond_struct_t;

cond_struct_t cond = {0, 0, SGX_THREAD_COND_INITIALIZER, SGX_THREAD_MUTEX_INITIALIZER};

void t_print(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

static void counter_aex_handler(const sgx_exception_info_t *info, const void * args)
{
    /*
    a custom handler that will be called when an AEX occurs, storing the number of ADD operations (performed in another thread) in a global array. This allows you to 
    know when AEX occurs (the number of ADD operations increases linearly) and how often it occurs.
    */
    (void)info;
    (void)args;
    count_aex[aex_count] = add_count;
    aex_count++;
}

static void monitor_aex_handler(const sgx_exception_info_t *info, const void * args)
{
    /*
    a custom handler that will be called when an AEX occurs, storing the number of ADD operations (performed in another thread) in a global array. This allows you to 
    know when AEX occurs (the number of ADD operations increases linearly) and how often it occurs.
    */
    (void)info;
    (void)args;
    monitor_aex[monitor_aex_count] = add_count;
    monitor_aex_count++;
}

void printArray(long long int *arr, long long int size){
    /*
    Print a array of size SIZE, which contains the number of ADD operations performed before each AEX occurs.
    */
    for(int i = 0; i < size ; i++){
        t_print("%d;%lld\n", i, arr[i]);
    }
}

void countADD(void){
    /*
    The function that will be called in another thread to perform ADD operations.
    */
    //see_pid("countADD");
    const char* args = NULL; 
    sgx_aex_mitigation_node_t node;
    sgx_register_aex_handler(&node, counter_aex_handler, (const void*)args);
    cond_struct_t *c = &cond;
    while (!c->isCounting);
    while(c->isCounting == 1){
        add_count++; 
    }
    sgx_unregister_aex_handler(counter_aex_handler);
}


void main_thread(int sleep_time, int sleep_inside_enclave, int verbosity){
    /*
    the main thread that will be called by the application.
    */
    //see_pid("main_thread");
    cond_struct_t *c = &cond;
    
    const char* args = NULL; 
    sgx_aex_mitigation_node_t node;
    sgx_register_aex_handler(&node, monitor_aex_handler, (const void*)args);
    
    c->isCounting = 1;
    switch(sleep_inside_enclave){
        case 0:
            ocall_sleep(&sleep_time);
        break;
        case 1:
        {
            long long int timestamp_start = -1;
            ocall_readTSC(&timestamp_start);
            while(tsc-timestamp_start < 3000000000*sleep_time){
                ocall_readTSC(&tsc);
            }
        }
        break;
        case 2:
        {
            for( long long int counter = 0; counter < 529*sleep_time; counter++){
                for(int i = 0; i < 1000000; i++);
            }
        }
        break;
        case 3:
        {
            long long int counter = 1500000000;
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
        }
        break;
    }
    c->isCounting = 0;
    sgx_unregister_aex_handler(monitor_aex_handler);

    if(verbosity>=1)
    {
        t_print("idx;count\n");
        printArray(count_aex, aex_count);
    }
    if(verbosity>=2)
    {
        t_print("idx;monitor_aex_count\n");
        printArray(monitor_aex, monitor_aex_count);
    }
    if(verbosity==1)
    {
        t_print("%lld;%lld\n", aex_count, add_count);
    }
    if(verbosity>=2)
    {
        t_print("counter_aex_count;monitor_aex_count;final_count\n");
        t_print("%lld;%lld;%lld\n", aex_count, monitor_aex_count, add_count);
    }
}