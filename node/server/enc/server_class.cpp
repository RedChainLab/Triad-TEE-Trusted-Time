#include <iostream>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstring>
#include "server_class.h"


Server::Server(int port, int* node_port, cond_runtime_t* rs): port(port), runtime_scheduler(rs) {
    /*
    In : int port, int* node_port, cond_runtime_t* rs
    Out: Server object
    Description: Constructor of the server class. It initializes the server socket and the SSL context
    */
    t_print("SERVER : Initializing server with port %d\n", port);
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    server_sock = create_socket(port);
    ctx = init_server_ctx();
    if(!ctx){
        t_print("SERVER : Unable to create SSL context\n");
        return;
    }
    // Initialize clients array
    for (int i = 0; i < NB_TOTAL; i++) {
        clients[i].socket_fd = -1;
        clients[i].ssl_session = nullptr;
    }
    t_print("SERVER : initializing done\n");
}

Server::~Server() {
    /*
    In : void
    Out: void
    Description: Destructor of the server class. It closes the server socket and frees the SSL context
    */
    int ret;
    ocall_close(&ret, server_sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
}

int Server::create_socket(int port) {
    /*
    In : int port
    Out: ERROR_RETURN if the socket could not be created, the socket file descriptor otherwise
    Description: Creates a socket and binds it to the specified port
    */
    int sock;
    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        t_print("Unable to create socket");
        return ERROR_RETURN;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        t_print("Unable to bind");
        return ERROR_RETURN;
    }

    if (listen(sock, 2) < 0) {
        t_print("Unable to listen");
        return ERROR_RETURN;
    }

    return sock;
}

SSL_CTX* Server::init_server_ctx() {
    /*
    In : void
    Out: nullptr if the SSL context could not be created, the SSL context otherwise
    Description: Initializes the SSL context for the server
    */
    X509* cert = nullptr;
    EVP_PKEY* pkey = nullptr;
    SSL_CONF_CTX* ssl_confctx = SSL_CONF_CTX_new();
    SSL_CTX* ctx = nullptr;

    if ((ctx = SSL_CTX_new(TLS_client_method())) == nullptr)
    {
        t_print(TLS_CLIENT "unable to create a new SSL context\n");
        return nullptr;
    }

    if (initalize_ssl_context(ssl_confctx, ctx) != SGX_SUCCESS)
    {
        t_print(TLS_CLIENT "unable to create a initialize SSL context\n ");
        return nullptr;
    }
    // specify the verify_callback for custom verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, &verify_callback);
    //t_print(TLS_CLIENT "load cert and key\n");
    if (load_tls_certificates_and_keys(ctx, cert, pkey) != 0)
    {
        t_print(TLS_CLIENT
               " unable to load certificate and private key on the client\n");
        return nullptr;
    }
    return ctx;
}

void Server::handle_client(node_connection &client){
    /*
    In: node_connection client
    Out: void
    Description: Handles the client connection. If the client is connected, 
    it receives the UDP packet and updates the runtime_scheduler accordingly. 
    If the client is not connected, it receives the key and iv from the client and 
    closes the connection.
    */
    unsigned char ciphertext[128];
    char buffer_uncyphered[128] = {0};

    unsigned char decryptedtext[128];
    int already_asked[NB_TOTAL] = {0};
    int bytes_read = 0;
    int res = 0;
    long long epoch = 0;
    
    //The client has been calibrated and is ready to receive the timestamps
    if(client.is_connected == 1 && runtime_scheduler->isCalibrating == 0){
        res = receive_udp_packet(client, &runtime_scheduler->timestamps, already_asked, &epoch); 
        //received timestamps from another node, the timestamp is updated
        if (res == TIMESTAMP){
            t_print("SERVER : ts received from other node : %lld\n", runtime_scheduler->timestamps);
            sgx_thread_mutex_lock(&runtime_scheduler->mutex);
            if(epoch - runtime_scheduler->timestamps > 0){
                runtime_scheduler->epoch = epoch;
                runtime_scheduler->epoch -= runtime_scheduler->timestamps;
            }
            sgx_thread_mutex_unlock(&runtime_scheduler->mutex);       
        }
        //received timestamps from the trusted server, the timestamps thus needs to be 
        //forwarded to the client
        /*
        else if(res == CALIBRATION_ASK_TIME || res == DELAYED || res == NOT_DELAYED){
            //pas censé arriver
            t_print("SERVER : ts received from trusted server: %lld\n", runtime_scheduler->timestamps);
            sgx_thread_mutex_lock(&runtime_scheduler->mutex);
            if(epoch - runtime_scheduler->timestamps > 0){
                runtime_scheduler->epoch = epoch;
                runtime_scheduler->epoch -= runtime_scheduler->timestamps;
            }
            runtime_scheduler->shouldSend = 1;
            sgx_thread_mutex_unlock(&runtime_scheduler->mutex);
        }
        */
        //A timestamps was asked by res nodes. already_asked is updated to inform the client
        //side which nodes needs to receive the timestamps
        else if(res == PORT){
            sgx_thread_mutex_lock(&runtime_scheduler->mutex);
            runtime_scheduler->isAsking = 1;
            t_print("SERVER : received request from %d nodes\n", res);
            for(int i = 0; i < res; i++){
                runtime_scheduler->dest[i] = already_asked[i];
            }
            sgx_thread_mutex_unlock(&runtime_scheduler->mutex);
        }

    }
    //The node has to be calibrated
    else if(client.is_connected == 1 && runtime_scheduler->isCalibrating == 1){
        res = receive_udp_packet(client, &runtime_scheduler->timestamps, nullptr, &epoch);
        sgx_thread_mutex_lock(&runtime_scheduler->mutex);
        runtime_scheduler->isCounting = 0;
        if(res == NOT_DELAYED){
            runtime_scheduler->canSend = NOT_DELAYED;
            //t_print("SERVER : canSend : %d\n", runtime_scheduler->canSend);
        }
        else if(res == DELAYED){
            //t_print("\n\n\n\n SERVER : DELAYED\n\n\n\n");
            runtime_scheduler->canSend = DELAYED;
            //t_print("SERVER : canSend : %d\n", runtime_scheduler->canSend);
        }
        else if(res = CALIBRATION_COLD_START){
            t_print("SERVER : CALIBRATION_COLD_START\n");
            runtime_scheduler->canSend = NOT_DELAYED;
            //t_print("SERVER : canSend : %d\n", runtime_scheduler->canSend);
        }
        else{
            t_print("SERVER : received unknown message\n");
            runtime_scheduler->canSend = NOT_DELAYED;
        }
        runtime_scheduler->epoch = epoch;
        runtime_scheduler->epoch -= runtime_scheduler->timestamps;
        sgx_thread_mutex_unlock(&runtime_scheduler->mutex);

    }
    
    //The symmetric keys were not already exchanged. the key is send securlly
    //via a TLS connection and stored on both ends
    else{
        bytes_read = SSL_read(client.ssl_session, ciphertext, sizeof(ciphertext));
        if (bytes_read <= 0) {
            int ssl_error = SSL_get_error(client.ssl_session, bytes_read);
            t_print("ssl_error: %d\n", ssl_error);
            if (ssl_error == SSL_ERROR_ZERO_RETURN || bytes_read == 0) 
                t_print("Client disconnected\n");
            else {
                t_print("SSL_read failed\n");
                return;
            }
            close_ssl_connection(client);
        }
        if(receive_key_iv((char*) ciphertext, client.key, KEY_SIZE, client.iv, IV_SIZE)){
            client.is_connected = 1;
            //once recevied, the key is used to encrypt the message and the ssl connection is closed
            close_ssl_connection(client);
        }
    }
}

void Server::run() {
    /*
    In: void
    Out: void
    Description: Main function of the server. It first initializes the SSL context
    and the server socket, then it listens for incoming connections. When a connection
    is established, the infos from the incomming connections are stored in the node_connection
    structure. The server then listens for incoming messages and updates the runtime_scheduler
    to indicate what operations need to be performed by the client side.
    */
    fd_set readfds;
    int max_sd;
    int ret;
    struct timeval timeout;
    X509* certificate = nullptr;
    EVP_PKEY* pkey = nullptr;
    SSL_CONF_CTX* ssl_confctx = SSL_CONF_CTX_new();

    SSL_CTX* ssl_server_ctx = nullptr;
    int client_sock = -1;
    

    if ((ssl_server_ctx = SSL_CTX_new(TLS_server_method())) == nullptr)
    {
        t_print(TLS_SERVER "unable to create a new SSL context\n");
        goto exit;
    }

    if (initalize_ssl_context(ssl_confctx, ssl_server_ctx) != SGX_SUCCESS)
    {
        t_print(TLS_SERVER "unable to create a initialize SSL context\n ");
        goto exit;
    }
    SSL_CTX_set_verify(ssl_server_ctx, SSL_VERIFY_PEER, &verify_callback);
    
    if (load_tls_certificates_and_keys(ssl_server_ctx, certificate, pkey) != 0)
    {
        t_print(TLS_SERVER
               " unable to load certificate and private key on the server\n ");
        goto exit;
    }
    
    while (true) {
        //Create the server socket if it does not exist
        if(server_sock == -1){
            server_sock = create_socket(port);
        }       
        //reinitialize the fd_set and add the server_sock to the set
        FD_ZERO(&readfds);
        FD_SET(server_sock, &readfds);
        max_sd = server_sock;
        
        //add the connected nodes to the fd_set
        for (int i = 0; i < NB_TOTAL; i++) {
            if (clients[i].socket_fd > 0) {
                FD_SET(clients[i].socket_fd, &readfds);
            }
            if (clients[i].socket_fd > max_sd) {
                max_sd = clients[i].socket_fd;
            }
        }
        int nfds = max_sd + 1;

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        //survey the fd_set for incoming connections
        ocall_select(&ret, nfds, &readfds, &timeout);
        if ((ret < 0) && (errno != EINTR)) {
            continue;
        }        

        //add the new connection to the clients array
        if (FD_ISSET(server_sock, &readfds)){
            struct sockaddr_in addr;
            socklen_t len = sizeof(addr);
            client_sock = accept(server_sock, (struct sockaddr*)&addr, &len);
            if (client_sock < 0) {
                t_print("Unable to accept\n");
                continue;
            }
            SSL* ssl_session = SSL_new(ssl_server_ctx);
            ret = SSL_set_fd(ssl_session, client_sock);
            if(ret == 0){
                t_print("SERVER : Unable to set SSL file descriptor\n");
                continue;
            }
            if (SSL_accept(ssl_session) <= 0) {
                t_print("SERVER : SSL_accept failed\n");
                ocall_close(&ret, client_sock);  
            } 
            else {
                for (int i = 0; i < NB_TOTAL; i++) {
                    if (clients[i].socket_fd == -1) {
                        clients[i].socket_fd = client_sock;
                        clients[i].ssl_session = ssl_session;
                        t_print("SERVER : New connection on socket %d\n", client_sock);
                        break;
                    }
                }
            }
        }

        //handle the incoming messages
        //if(runtime_scheduler->isCalibrating == 0){
        for (int i = 0; i < NB_TOTAL; i++) {
            if (clients[i].socket_fd != -1 && FD_ISSET(clients[i].socket_fd, &readfds)) {
                handle_client(clients[i]);
            }
        }
    }

    exit:
    for(int i = 0; i < NB_TOTAL; i++){
        if(clients[i].socket_fd != -1){
            close_ssl_connection(clients[i]);
        }
    }
    if (ret != 0)
        t_print(TLS_SERVER "OCALL: error closing client socket\n");
    ocall_close(&ret, server_sock);
    if (ret != 0)
        t_print(TLS_SERVER "OCALL: error closing server socket\n");
    if (ssl_server_ctx)
        SSL_CTX_free(ssl_server_ctx);
    if (ssl_confctx)
        SSL_CONF_CTX_free(ssl_confctx);
    if (certificate)
        X509_free(certificate);
    if (pkey)
        EVP_PKEY_free(pkey);
    return;
}
