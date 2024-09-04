#include <iostream>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstring>
#include "server.h"

#define CERT_FILE "server.crt"
#define KEY_FILE "server.key"

const int HEX_KEY_SIZE = KEY_SIZE * 2 + 1; // 2 chars per byte + null terminator
const int HEX_IV_SIZE = IV_SIZE * 2 + 1;  // 2 chars per byte + null terminator

Server::Server(int p): port(p) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    server_sock = create_socket(port);
    ctx = init_server_ctx();
    load_certificates(ctx, CERT_FILE, KEY_FILE);

    // Initialize clients array
    for (int i = 0; i < NB_NODE; i++) {
        node_clients[i].socket_fd = -1;
        node_clients[i].ssl_session = nullptr;
    }
}

Server::~Server() {
    int ret;
    close(server_sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
}

int Server::create_socket(int port) {
    int sock;
    struct sockaddr_in addr;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    //sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        t_print("Unable to create socket");
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        t_print("Unable to bind");
        return -1;
    }

    if (listen(sock, 1) < 0) {
        t_print("Unable to listen");
        return -1;
    }

    return sock;
}

SSL_CTX* Server::init_server_ctx() {
    
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    method = SSLv23_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        t_print("Unable to create SSL context\n");
        return NULL;
        //ERR_print_errors_fp(stderr);
        //exit(EXIT_FAILURE);
    }
    return ctx;
    
}


void Server::load_certificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile) {
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        t_print("Unable to load certificate\n");
        return;
        //ERR_print_errors_fp(stderr);
        //exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        t_print("Unable to load private key\n");
        return;
        //ERR_print_errors_fp(stderr);
        //exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        t_print("Private key does not match the public certificate\n");
        return;
        //std::cerr << "Private key does not match the public certificate\n";
        //exit(EXIT_FAILURE);
    }
}

int Server::handle_client(node_connection &client, int i){
    unsigned char ciphertext[128];
    char buffer_uncyphered[1024] = {0};

    unsigned char decryptedtext[128];

    int bytes_read = 0;
    int error = 0;
    t_print("SERVER : handiling client\n");
    if(client.is_connected == 1){
        //t_print("CLIENT : client is connected\n");
        //receive_udp_packet(client, client.socket_fd);
        t_print("SERVER : just before receiving UDP packet\n");
        receive_udp_packet(client, client.socket_fd, client.key, client.iv);
        return 0;      
    }
    else{
        bytes_read = SSL_read(client.ssl_session, ciphertext, sizeof(ciphertext));
        if (bytes_read <= 0) {
            int ssl_error = SSL_get_error(client.ssl_session, bytes_read);
            t_print("ssl_error: %d\n", ssl_error);
            if (ssl_error == SSL_ERROR_ZERO_RETURN || bytes_read == 0) 
                t_print("Client disconnected\n");
            else {
                t_print("SSL_read failed\n");
                //ERR_print_errors_fp(stderr);
                return -1;
            }
            close_ssl_connection(client);
        }
        t_print("SERVER : just before decrypting\n");
        if(receive_key_iv((char*) ciphertext, client.key, KEY_SIZE, client.iv, IV_SIZE)){
            client.is_connected = 1;
            close_ssl_connection(client);
            t_print("after setting up : client.socket_fd : %d\n", client.socket_fd);
            return 0;
        }
    }
    return 0;
}

void Server::run() {
    fd_set readfds;
    int max_sd;
    int ret;
    struct timeval timeout;
    
    while (true) {
        if(server_sock == -1){
            server_sock = create_socket(port);
        }
        FD_ZERO(&readfds);
        FD_SET(server_sock, &readfds);
        max_sd = server_sock;

        for (int i = 0; i < NB_NODE; i++) {
            if (node_clients[i].socket_fd > 0) {
                FD_SET(node_clients[i].socket_fd, &readfds);
            }
            if (node_clients[i].socket_fd > max_sd) {
                max_sd = node_clients[i].socket_fd;
            }
        }

        int osef = max_sd + 1;
        timeout.tv_sec = 1/* seconds */;
        timeout.tv_usec = 0/* microseconds */;

        int activity = select(max_sd + 1, &readfds, NULL, NULL, &timeout);
        if ((activity < 0) && (errno != EINTR)) {
            perror("Select error");
            continue;
        }
        
        if (FD_ISSET(server_sock, &readfds)){//&readfds)) {
            struct sockaddr_in addr;
            socklen_t len = sizeof(addr);
            int client_sock = accept(server_sock, (struct sockaddr*)&addr, &len);
            if (client_sock < 0) {
                t_print("Unable to accept\n");
                continue;
            }
            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, client_sock);
            if (SSL_accept(ssl) <= 0) {
                //ERR_print_errors_fp(stderr);
                close(client_sock);
                
            } else {
                for (int i = 0; i < NB_NODE; i++) {
                    if (node_clients[i].socket_fd == -1) {
                        node_clients[i].socket_fd = client_sock;
                        node_clients[i].ssl_session = ssl;
                        t_print("New connection on socket %d\n", client_sock);
                        //std::cout << "New connection on socket " << client_sock << std::endl;
                        break;
                    }
                }
            }
        }
        for (int i = 0; i < NB_NODE; i++) {
            if (FD_ISSET(node_clients[i].socket_fd, &readfds)) {
                int val = handle_client(node_clients[i], i);
                if (val == 1){
                    for(int j = 0; j < NB_NODE; j++){
                        if (node_clients[j].ssl_session != nullptr) {
                            SSL_shutdown(node_clients[j].ssl_session);
                            SSL_free(node_clients[j].ssl_session);
                            node_clients[j].ssl_session = nullptr;
                        }
                        if (node_clients[j].socket_fd != -1) {
                            close(node_clients[j].socket_fd);
                            node_clients[j].socket_fd = -1;
                        }
                        if (ctx != nullptr) {
                            SSL_CTX_free(ctx);
                            ctx = nullptr;
                        }
                        EVP_cleanup();
                        close(server_sock);
                    }
                    exit(0);
                }
            }
            /*
            else{
                t_print("SERVER : no client connected\n");
            }
            */

           /* COUCOU */
        }
    }
}
