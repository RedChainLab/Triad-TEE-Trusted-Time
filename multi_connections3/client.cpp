#include "client.h"
#include <iostream>
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

#define SERVER_IP "127.0.0.1"
#define RETRY_INTERVAL 2 // Retry interval in seconds


Client::Client(const char* server_ip, int* port) {
    ctx = init_client_ctx();
    for(int i = 0; i < NB_NODE; i++){
        node_connections[i].node_name = server_ip;
        node_connections[i].node_port = port[i];
        node_connections[i].socket_fd = -1;
        node_connections[i].ssl_session = nullptr;
        if ((node_connections[i].ssl_session = SSL_new(ctx)) == nullptr)
        {
            t_print(" CLIENT : Unable to create a new SSL connection state object\n");
        }
        
        node_connections[i].is_connected = 0;
    }
    t_print("CLIENT : Client initialized\n");

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

Client::~Client() {
    close(server_sock);
    for(int i = 0; i < NB_NODE; i++){
        close(node_connections[i].socket_fd);
        SSL_free(node_connections[i].ssl_session);
    }
    EVP_cleanup();
}

void Client::wait_in_enclave(int seconds) {
    for (int j = 0; j < 75*seconds; j++){
        for(int i = 0; i < 10000000; i++){
            
        }
    }
}

int Client::create_socket(const char* server_ip, int port) {
    int sock;
    int ret;
    struct sockaddr_in addr;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        t_print("Unable to create socket");
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr =  inet_addr2(server_ip);
    /*
    if (inet_pton(AF_INET, server_ip, &addr.sin_addr) <= 0) {
        t_print("Invalid address/ Address not supported");
        return -1;
    }
    */
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        wait_in_enclave(RETRY_INTERVAL); // Wait before retrying
    } else {
        t_print("CLIENT : Connected to the server\n");
        return sock;
    }
    return -1;
}

SSL_CTX* Client::init_client_ctx() {
    
    const SSL_METHOD* method;

    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        t_print("CLIENT : Unable to create a new SSL context\n");
        return NULL;
        //ERR_print_errors_fp(stderr);
        //exit(EXIT_FAILURE);
    }
    return ctx;
}


void Client::establish_socket(){
    for (int i = 0; i < NB_NODE; i++) {
            if(node_connections[i].socket_fd == -1){
                int sockfd = create_socket(node_connections[i].node_name, node_connections[i].node_port);
                if (sockfd == -1) {
                    //fprintf(stderr, "Failed to create socket for server %s:%s\n", node_connections[i].node_name, node_connections[i].node_port);
                    continue;
                }  
                else{         
                    node_connections[i].socket_fd = sockfd;
                    node_connections[i].ssl_session = SSL_new(ctx);
                    SSL_set_fd(node_connections[i].ssl_session, sockfd);
                    if (SSL_connect(node_connections[i].ssl_session) != 1) {
                        printf("SSL_connect failed\n");
                        //ERR_print_errors_fp(stderr);
                        close(sockfd);
                        SSL_free(node_connections[i].ssl_session);
                        node_connections[i].ssl_session = NULL;
                        node_connections[i].socket_fd = -1;
                    }
                    else{
                        printf("CLIENT : Connection established with server %s:%d\n", node_connections[i].node_name, node_connections[i].node_port);
                    }
            }
        }
    }
}
int Client::run() {
    t_print("CLIENT : Running client\n");
    long long ts = 0;
    std::string cryptographic_key;
    std::string port;
    establish_socket();
    int bytes_written;
    int error = 0;
    int ret = 1;
    
    while(true){
        t_print("CLIENT : Waiting for server\n");
        establish_socket();
        for(int i = 0; i < NB_NODE; i++){
            if(node_connections[i].socket_fd != -1 && node_connections[i].is_connected == 0){
                //printf("Generating key for server %s:%d\n", node_connections[i].node_name, node_connections[i].node_port);
                exchange_key(node_connections[i]);
            }
            
            if(node_connections[i].socket_fd != -1 && node_connections[i].is_connected == 1){
                unsigned char plaintext[] = "This is a secret message.";
                unsigned char ciphertext[128];

                int ciphertext_len = aes_encrypt(plaintext, strlen((char*)plaintext), node_connections[i].key, node_connections[i].iv, ciphertext);
                if (ciphertext_len == -1) {
                    t_print("Encryption failed.\n");
                    //std::cerr << "Encryption failed." << std::endl;
                    return EXIT_FAILURE;
                }
                send_udp_packet(node_connections[i], node_connections[i].node_name, node_connections[i].node_port, node_connections[i].socket_fd, ciphertext, ciphertext_len);
                wait_in_enclave(1);               
            }
            else{
                t_print("No server available\n");
            }
        }
    }
    
clean:
    for(int i = 0; i < NB_NODE; i++){
        close_ssl_connection(node_connections[i]);  
    }
    SSL_CTX_free(ctx);
    return ret;
}

/*
void readTSC(long long* ts) {
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

*/


