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
#define MAX_CLIENTS 2

const int HEX_KEY_SIZE = KEY_SIZE * 2 + 1; // 2 chars per byte + null terminator
const int HEX_IV_SIZE = IV_SIZE * 2 + 1;  // 2 chars per byte + null terminator

Server::Server(int p): port(p) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    server_sock = create_socket(port);
    ctx = init_server_ctx();
    load_certificates(ctx, CERT_FILE, KEY_FILE);

    // Initialize clients array
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].socket_fd = -1;
        clients[i].ssl_session = nullptr;
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
/*
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
*/
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

void Server::handle_client(node_connection &client, int i){
    unsigned char ciphertext[128];
    char buffer_uncyphered[1024] = {0};

    unsigned char decryptedtext[128];

    int bytes_read = 0;
    int error = 0;
    
    if(client.is_connected == 1){
        receive_udp_packet(client, client.socket_fd, client.key, client.iv);       
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
                return;
            }
            close_ssl_connection(client);
        }
        if(receive_key_iv((char*) ciphertext, client.key, KEY_SIZE, client.iv, IV_SIZE)){
            client.is_connected = 1;
            close_ssl_connection(client);
            t_print("after setting up : client.socket_fd : %d\n", client.socket_fd);
        }
        //close_ssl_connection(client); //Il faut que l'autre ai aussi envoyé sa clef avant de fermer la connexion
    }
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

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].socket_fd > 0) {
                FD_SET(clients[i].socket_fd, &readfds);
            }
            if (clients[i].socket_fd > max_sd) {
                max_sd = clients[i].socket_fd;
            }
        }
        int osef = max_sd + 1;
        /*
        int activity = ocall_select(&ret, &max_sd, &readfds, NULL, NULL, NULL);//select(max_sd + 1, &readfds, NULL, NULL, NULL);
        if ((activity < 0) && (errno != EINTR)) {
            t_print("Select error\n");
            continue;
        }
        */
        timeout.tv_sec = 1/* seconds */;
        timeout.tv_usec = 0/* microseconds */;
        //t_print("ECALL: calling ocall_select with nfds = %d\n", max_sd);
        //int ret = select(osef, &readfds, NULL, NULL, NULL);//&timeout);
        //t_print("ECALL: ocall_select returned %d\n", ret);
        //if (ret < 0) {
        //    t_print("ECALL: Select error\n");
        //} 
        //else if (ret == 0) {  
            //t_print("ECALL: Select timeout\n");
        //}
        int activity = select(max_sd + 1, &readfds, NULL, NULL, &timeout);
        if ((activity < 0) && (errno != EINTR)) {
            perror("Select error");
            continue;
        }
        printf("SERVER : activity : %d\n", activity);
        
        if (FD_ISSET(server_sock, &readfds)){//&readfds)) {
            struct sockaddr_in addr;
            socklen_t len = sizeof(addr);
            int client_sock = accept(server_sock, (struct sockaddr*)&addr, &len);
            if (client_sock < 0) {
                t_print("Unable to accept\n");
                continue;
            }
            t_print("SERVER : Connection accepted\n");
            SSL* ssl = SSL_new(ctx);
            t_print("SERVER : SSL session created\n");
            SSL_set_fd(ssl, client_sock);
            if (SSL_accept(ssl) <= 0) {
                //ERR_print_errors_fp(stderr);
                close(client_sock);
                
            } else {
                t_print("SERVER : SSL connection established\n");
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (clients[i].socket_fd == -1) {
                        clients[i].socket_fd = client_sock;
                        clients[i].ssl_session = ssl;
                        t_print("New connection on socket %d\n", client_sock);
                        //std::cout << "New connection on socket " << client_sock << std::endl;
                        break;
                    }
                }
            }
        }
        for (int i = 0; i < NB_NODE; i++) {
            if (FD_ISSET(clients[i].socket_fd, &readfds)) {
                handle_client(clients[i], i);
            }
            /*
            else{
                t_print("SERVER : no client connected\n");
            }
            */
        }
    }
}
