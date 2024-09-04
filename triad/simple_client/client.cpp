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
        node_servers[i].node_name = server_ip;
        node_servers[i].node_port = port[i];
        node_servers[i].socket_fd = -1;
        node_servers[i].ssl_session = nullptr;
        if ((node_servers[i].ssl_session = SSL_new(ctx)) == nullptr)
        {
            t_print(" CLIENT : Unable to create a new SSL connection state object\n");
        }
        
        node_servers[i].is_connected = 0;
    }
    t_print("CLIENT : Client initialized\n");

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

Client::~Client() {
    close(server_sock);
    for(int i = 0; i < NB_NODE; i++){
        close(node_servers[i].socket_fd);
        SSL_free(node_servers[i].ssl_session);
    }
    EVP_cleanup();
}

void Client::wait_in_enclave(int seconds) {
    for (int j = 0; j < 75*seconds; j++){
        for(int i = 0; i < 1000000; i++){
            
        }
    }
}

int Client::create_socket(const char* server_ip, int port) {
    int sock;
    int ret;
    struct sockaddr_in addr;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    //sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        t_print("Unable to create socket");
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip, &addr.sin_addr) <= 0) {
        t_print("Invalid address/ Address not supported");
        return -1;
    }
    
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
    }
    return ctx;
}


void Client::establish_socket(){
    for (int i = 0; i < NB_NODE; i++) {
            if(node_servers[i].socket_fd == -1){
                int sockfd = create_socket(node_servers[i].node_name, node_servers[i].node_port);
                if (sockfd == -1) {
                    continue;
                }  
                else{         
                    node_servers[i].socket_fd = sockfd;
                    node_servers[i].ssl_session = SSL_new(ctx);
                    SSL_set_fd(node_servers[i].ssl_session, sockfd);
                    if (SSL_connect(node_servers[i].ssl_session) != 1) {
                        printf("SSL_connect failed\n");
                        //ERR_print_errors_fp(stderr);
                        close(sockfd);
                        SSL_free(node_servers[i].ssl_session);
                        node_servers[i].ssl_session = NULL;
                        node_servers[i].socket_fd = -1;
                    }
                    else{
                        printf("CLIENT : Connection established with server %s:%d\n", node_servers[i].node_name, node_servers[i].node_port);
                    }
            }
        }
    }
}
int Client::run() {
    long long ts = 0;
    std::string cryptographic_key;
    std::string port;
    //establish_socket();
    int bytes_written;
    int error = 0;
    int ret = 1;
    int index = 0;
    
    while(true){
        index++;
        index = index % NB_NODE;
        establish_socket();
        for(int i = 0; i < NB_NODE; i++){
            if(node_servers[i].socket_fd != -1 && node_servers[i].is_connected == 0){
                //printf("Generating key for server %s:%d\n", node_servers[i].node_name, node_servers[i].node_port);
                exchange_key(node_servers[i]);
            }
            
            if(node_servers[i].socket_fd != -1 && node_servers[i].is_connected == 1){
                unsigned char plaintext[] = "p;12300";
                unsigned char ciphertext[128];
                int ciphertext_len = aes_encrypt(plaintext, strlen((char*)plaintext), node_servers[i].key, node_servers[i].iv, ciphertext);
                if (ciphertext_len == -1) {
                    t_print("Encryption failed.\n");
                    return EXIT_FAILURE;
                }
                //send_udp_packet(node_servers[i], node_servers[i].node_name, node_servers[i].node_port, node_servers[i].socket_fd, ciphertext, ciphertext_len);
                send_udp_packet(node_servers[i], node_servers[i].node_name, node_servers[i].node_port, node_servers[i].socket_fd, ciphertext, ciphertext_len);
                sleep(2);               
            }
            /*
            else{
                //t_print("No server available\n");
            }
            */
        }
    }
    
clean:
    for(int i = 0; i < NB_NODE; i++){
        close_ssl_connection(node_servers[i]);  
    }
    SSL_CTX_free(ctx);
    return ret;
}
