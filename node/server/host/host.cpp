/**
*
* MIT License
*
* Copyright (c) Open Enclave SDK contributors.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE
*
*/

#include "sgx_urts.h"
#include <stdio.h>
#include "tls_server_u.h"
#include <iostream>
#include <thread>
#include <future>
#include <sgx_uswitchless.h>
#include <ctime>
#include <fcntl.h>
#include <stdlib.h>
#include <threads.h>
#include <unistd.h>


#define F_DUPFD		0	/* Duplicate file descriptor.  */
#define F_GETFD		1	/* Get file descriptor flags.  */
#define F_SETFD		2	/* Set file descriptor flags.  */
#define F_GETFL		3	/* Get file status flags.  */
#define F_SETFL		4	/* Set file status flags.  */
#define LOOP_OPTION "-server-in-loop"
/* Global EID shared by multiple threads */

sgx_enclave_id_t server_global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

int ocall_close(int fd)
{
    return close(fd);
}


/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}


sgx_status_t initialize_enclave(const char *enclave_path, const sgx_uswitchless_config_t* us_config)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    const void* enclave_ex_p[32] = { 0 };

    enclave_ex_p[SGX_CREATE_ENCLAVE_EX_SWITCHLESS_BIT_IDX] = (const void*)us_config;

    ret = sgx_create_enclave_ex(enclave_path, SGX_DEBUG_FLAG, NULL, NULL, &server_global_eid, NULL, SGX_CREATE_ENCLAVE_EX_SWITCHLESS, enclave_ex_p);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return ret;
    }

    return ret;
}

void terminate_enclave()
{
    sgx_destroy_enclave(server_global_eid);
    printf("Host: Enclave successfully terminated.\n");
}

void set_thread_affinity(int core_id) {
    /*
    set the affinity of the current thread to the core_id
    */
    pthread_t t = pthread_self();
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    int s = pthread_setaffinity_np(t, sizeof(cpu_set_t), &cpuset);
    if (s != 0) {
        std::cerr << "Error setting thread affinity: " << strerror(s) << std::endl;
    }
}

void set_affinity(int core_id) {
    /*
    set the affinity of the current thread to the core_id
    */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    // Get the current thread (which is the main thread in this case)
    pid_t pid = getpid();
    //printf("pid: %d\n", pid);
    
    int result = sched_setaffinity(pid, sizeof(cpu_set_t), &cpuset);
    if (result != 0) {
        std::cerr << "Error setting thread affinity: " << strerror(result) << std::endl;
    } else {
        //std::cout << "Thread affinity set to CPU " << core_id << std::endl;
    }
    
}

void readTSC(long long* test) {
    #if defined(_MSC_VER) // MSVC specific
        *test = __rdtsc();
    #elif defined(__GNUC__) || defined(__clang__) // GCC or Clang specific
        unsigned int lo, hi;
        __asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
        *test = ((uint64_t)hi << 32) | lo;
    #else
    #error "Compiler not supported"
    #endif
}

int ocall_select(int nfds, fd_set* readfds, struct timeval* timeout) {
    int result = select(nfds, readfds, NULL, NULL, timeout);
    return result;
}

void add_thread(int core_id_add)
{
    set_thread_affinity(core_id_add)
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = count_add(server_global_eid);
    if (ret != SGX_SUCCESS)
        abort();
}

void startServer_thread(int server_port, int* node_port, int client_port, int trusted_server_port, int core_id_server)
{
    set_thread_affinity(core_id_server)
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = init_server(server_global_eid, server_port, node_port[0], node_port[1], client_port, trusted_server_port);
    if (ret != SGX_SUCCESS)
        abort();
}

void startClient_thread(int own_port, int* node_port, int client_port, int trusted_server_port, int core_id_client)
{
    set_thread_affinity(core_id_client)
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    init_client(server_global_eid, "127.0.0.1", own_port, node_port[0], node_port[1], client_port, trusted_server_port);
    if (ret != SGX_SUCCESS)
        abort();
}

void readTS_thread(int core_id_readTSC)
{
    set_thread_affinity(core_id_readTSC)
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = readTS(server_global_eid);
    if (ret != SGX_SUCCESS)
        abort();
}

void start_runtime(int own_port, int* node_port, int client_port, int trusted_server_port, int core_id_readTSC, int ccore_id_server, int core_id_client, int core_id_add)
{
    printf("HOST : Starting server\n");
    std::thread startServer(startServer_thread, own_port, node_port, client_port, trusted_server_port, core_id_server);
    printf("HOST : Starting client\n");
    std::thread startClient(startClient_thread, own_port, node_port, client_port, trusted_server_port, core_id_client);
    std::thread add(add_thread, core_id_add);
    std::thread readTS(readTS_thread, core_id_readTSC);

    readTS.join();
    startServer.join();
    sleep(1);
    startClient.join();
    add.join();
}

int main(int argc, const char* argv[])
{
    sgx_uswitchless_config_t us_config = SGX_USWITCHLESS_CONFIG_INITIALIZER;
    us_config.num_uworkers = 2;
    us_config.num_tworkers = 2;

    sgx_status_t result = SGX_SUCCESS;
    sgx_status_t status = SGX_SUCCESS;
    int ret = 0;
    int server_port = 0;
    int node1_port = 0;
    int node2_port = 0;
    int keep_server_up = 0; 

    if (argc == 10)
    {
        if (strcmp(argv[5], LOOP_OPTION) != 0)
        {
            printf(
                "Usage: %s TLS_SERVER_ENCLAVE_PATH <server_port> <node1_port> <node2_port> <core_id_readTSC><core_id_server><core_id_client><core_id_add>[%s]\n",
                argv[0],
                LOOP_OPTION);
            return 1;
        }
        else
        {
            keep_server_up = 1;
        }
    }
    else if (argc != 9)
    {
        printf(
            "Usage: %s TLS_SERVER_ENCLAVE_PATH -port:<port> [%s]\n",
            argv[0],
            LOOP_OPTION);
        return 1;
    }

    server_port = atoi(argv[2]);
    node1_port = atoi(argv[3]);
    node2_port = atoi(argv[4]);

    int core_id_readTSC = atoi(argv[5]);
    int core_id_server = atoi(argv[6]);
    int core_id_client = atoi(argv[7]);
    int core_id_add = atoi(argv[8]);


    int node_port[2] = {node1_port, node2_port};
    int core_id_parent;
    set_affinity(core_id_parent)

    printf("Host: Creating an tls server enclave\n");
    result = initialize_enclave(argv[1], &us_config);
    if (result != SGX_SUCCESS)
    {
        goto exit;
    }
    
    start_runtime(server_port, node_port, 12300, 12350, core_id_readTSC, core_id_server, core_id_client, core_id_add);
    printf("result : %d, ret : %d\n", result, ret);
    if (result != SGX_SUCCESS || ret != 0)
    {
        printf("Host: setup_tls_server failed\n");
        goto exit;
    }

exit:

    printf("Host: Terminating enclaves\n");
    terminate_enclave();

    printf("Host:  %s \n", (ret == 0) ? "succeeded" : "failed");
    return ret;
}
