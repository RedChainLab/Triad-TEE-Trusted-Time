#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cassert>
#include <map>
#include <thread>

#include "App.h"
#include "Enclave_u.h"

std::map<int, Node*> Node::nodes;
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

Node::Node(uint16_t _port) : port(_port), sock(-1), enclave_id(0)
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
    if(!this->setup_socket())
    {
        std::cerr << "Error: socket setup failed" << std::endl;
    }
    // launch thread to listen to incoming messages
    std::thread listenThread(&Node::listen, this);
    listenThread.detach();
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
    if (nodes.find(_port) == nodes.end())
    {
        std::cout << "Creating node instance..." << std::endl;
        nodes[_port] = new Node(_port);
        std::cout << "Node instance created: " << nodes[_port] << std::endl;
    }
    else
    {
        std::cout << "Node instance exists: " << nodes[_port] << std::endl;
    }
    return nodes[_port];
}

void Node::destroy_instance(uint16_t _port)
{
    if (!nodes.empty() && nodes.find(_port) != nodes.end())
    {
        std::cout << "Destroying node instance: " << nodes[_port] << std::endl;
        delete nodes[_port];
        nodes.erase(_port);
        std::cout << "Node instance destroyed." << std::endl;
    }
    else
    {
        std::cout << "Node instance does not exist. " << std::endl;
    }
}

int Node::get_timestamp()
{
    return 0;
}

bool Node::setup_socket()
{
    //creating a new server socket
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("server socket creation error...\n");
        exit(-1);
    }

    //binding the port to ip and port
    struct sockaddr_in serAddr;
    serAddr.sin_family = AF_INET;
    serAddr.sin_port = htons(this->port);
    serAddr.sin_addr.s_addr = INADDR_ANY;

    if ((bind(sock, (struct sockaddr*)&serAddr, sizeof(serAddr))) < 0) {
        perror("server socket binding error...\n");
        close(sock);
        exit(-1);
    }
    return sock >= 0;
}

void Node::listen()
{
    do
    {
        assert(sock >= 0);

        struct sockaddr_in cliAddr;
        socklen_t cliAddrLen = sizeof(cliAddr);
        char buff[1024] = {0};
        ssize_t readStatus = recvfrom(sock, buff, 1024, 0, (struct sockaddr*)&cliAddr, &cliAddrLen);
        if (readStatus < 0) {
            perror("reading error...\n");
            close(sock);
            exit(-1);
        }

        std::pair<std::string, uint16_t> cliAddrPair(inet_ntoa(cliAddr.sin_addr), ntohs(cliAddr.sin_port));
        siblings[cliAddrPair] += 1;
        std::cout << "Message received from: " << cliAddrPair.first << ":" << cliAddrPair.second << " = " << siblings[cliAddrPair] << std::endl;

        //write but in a string
        std::string arrivedMsg(buff);
        if (arrivedMsg.find("Request") != std::string::npos)
        {
            std::cout << "Request received from: " << inet_ntoa(cliAddr.sin_addr) << ":" << ntohs(cliAddr.sin_port) << std::endl;
            //print the message

            char msg[1024] = {0};
            sprintf(msg, "Response from %d\n", this->port);
            if (sendto(sock, msg, strlen(msg), 0, (struct sockaddr*)&cliAddr, cliAddrLen) < 0) {
                perror("sending error...\n");
                close(sock);
                exit(-1);
            }
        }
        else
        {
            std::cout << "Message received from: " << inet_ntoa(cliAddr.sin_addr) << ":" << ntohs(cliAddr.sin_port) << std::endl;
            std::cout.write(buff, readStatus);
        }
    } while (sock >= 0);
}

void Node::contactSibling(const char* siblIP, uint16_t siblPort)
{
    assert(sock >= 0);

    if (siblings.find(std::pair<std::string, uint16_t>(siblIP, siblPort)) != siblings.end())
    {
        std::cout << "Sibling already added: " << siblIP << ":" << siblPort << std::endl;
        return;
    }

    struct sockaddr_in serAddr;
    serAddr.sin_family = AF_INET;
    serAddr.sin_port = htons(siblPort);
    serAddr.sin_addr.s_addr = inet_addr(siblIP);

    char msg[1024] = {0};
    sprintf(msg, "Request to %d\n", siblPort);

    if (sendto(sock, msg, strlen(msg), 0, (struct sockaddr*)&serAddr, sizeof(serAddr)) < 0) {
        perror("sending error...\n");
        close(sock);
        exit(-1);
    }

    std::pair<std::string, uint16_t> cliAddrPair(siblIP, siblPort);
    siblings[cliAddrPair] = 0;

}

void Node::printSiblings()
{
    for (auto& sibl : siblings)
    {
        std::cout << sibl.first.first << ":" << sibl.first.second << " = " << sibl.second << std::endl;
    }
}