#include <iostream>

#include "sgx_urts.h"
#include "sgx_uswitchless.h"
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "App.h"
#include "Enclave_u.h"

Node* Node::node = nullptr;
const char* Node::ENCLAVE_FILE = "node/enclave.signed.so";

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
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
    {
        SGX_ERROR_MEMORY_MAP_FAILURE,
        "Failed to reserve memory for the enclave.",
        NULL
    },
};

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
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int Node::initialize_enclave(const sgx_uswitchless_config_t* us_config)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    const void* enclave_ex_p[32] = { 0 };

    enclave_ex_p[SGX_CREATE_ENCLAVE_EX_SWITCHLESS_BIT_IDX] = (const void*)us_config;

    ret = sgx_create_enclave_ex(ENCLAVE_FILE, SGX_DEBUG_FLAG, NULL, NULL, &enclave_id, NULL, SGX_CREATE_ENCLAVE_EX_SWITCHLESS, enclave_ex_p);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

void ocall_print_string(const char *str)
{
    printf("%s", str);
}


void ocall_readTSC(long long* ts) {
    /*
    Read the TSC register
    */
    #if defined(_MSC_VER) // MSVC specific
        *ts = __rdtsc();
    #elif defined(__GNUC__) || defined(__clang__) // GCC or Clang specific
        unsigned int lo, hi;
        __asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
        *ts = ((uint64_t)hi << 32) | lo;
    #else
    #error "Compiler not supported"
    #endif
}

void ocall_sleep(int* sec) {
    /*
    Sleep for sec seconds outside the enclave
    */
    //printf("Sleeping for %d seconds outside the enclave...\n", *sec);
    sleep(*sec);
    //printf("Done sleeping outside the enclave\n");
}

Node::Node(uint16_t _port) : port(_port), enclave_id(0)
{
    /* Configuration for Switchless SGX */
    sgx_uswitchless_config_t us_config = SGX_USWITCHLESS_CONFIG_INITIALIZER;
    us_config.num_uworkers = 1;
    us_config.num_tworkers = 1;

    /* Initialize the enclave */
    if (initialize_enclave(&us_config) < 0) 
    {
        std::cerr << "Error: enclave initialization failed" << std::endl;
        enclave_id = 0;
    } 
    else 
    {
        std::cout << "SGX enclave initialized: " << enclave_id << std::endl;
    }
    if(this->setup_sockets() < 0)
    {
        std::cerr << "Error: sockets setup failed" << std::endl;
    }
}

Node::~Node() 
{
    if (enclave_id != 0) 
    {
        sgx_destroy_enclave(enclave_id);
        std::cout << "SGX enclave destroyed: " << enclave_id << std::endl;
    }
}

Node* Node::get_instance(uint16_t _port)
{
    if (node == nullptr) 
    {
        std::cout << "Creating node instance..." << std::endl;
        node = new Node(_port);
        std::cout << "Node instance created: " << node << std::endl;
    }
    else
    {
        std::cout << "Node instance already exists: " << node << std::endl;
    }
    return node;
}

void Node::destroy_instance()
{
    if (node != nullptr) 
    {
        std::cout << "Destroying node instance: " << node << std::endl;
        delete node;
        node = nullptr;
        std::cout << "Node instance destroyed." << std::endl;
    }
    else
    {
        std::cout << "Node instance does not exist: " << node << std::endl;
    }
}

int Node::get_timestamp()
{
    return 0;
}

int Node::setup_sockets()
{
    int serSockDes = setup_server_socket();
    int cliSockDes = setup_client_socket();
    return (serSockDes && cliSockDes)?0:-1;
}

int Node::setup_client_socket()
{
    int cliSockDes;

    //create a socket
    if ((cliSockDes = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("client socket creation error...\n");
        exit(-1);
    }
    return cliSockDes;
}

int Node::setup_server_socket()
{
    int serSockDes;
    struct sockaddr_in serAddr;

    //creating a new server socket
    if ((serSockDes = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("server socket creation error...\n");
        exit(-1);
    }

    //binding the port to ip and port
    serAddr.sin_family = AF_INET;
    serAddr.sin_port = htons(this->port);
    serAddr.sin_addr.s_addr = INADDR_ANY;

    if ((bind(serSockDes, (struct sockaddr*)&serAddr, sizeof(serAddr))) < 0) {
        perror("server socket binding error...\n");
        close(serSockDes);
        exit(-1);
    }
    return serSockDes;
}