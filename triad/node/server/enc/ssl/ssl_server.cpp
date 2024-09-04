#include "ssl_server.h"
#include "ssl_common.h"
#include <cstdio>

bool is_out_of_enclave = false;
long long timestamps = 0;
//long long aex_count = 0;

#define MAX_CLIENTS 3

static cond_runtime_t runtime_scheduler = {NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, {0,0,0,0}, {0,0},
        SGX_THREAD_COND_INITIALIZER,SGX_THREAD_COND_INITIALIZER, SGX_THREAD_COND_INITIALIZER, SGX_THREAD_COND_INITIALIZER,
        SGX_THREAD_COND_INITIALIZER,SGX_THREAD_COND_INITIALIZER, SGX_THREAD_COND_INITIALIZER, SGX_THREAD_MUTEX_INITIALIZER};


static void my_aex_notify_handler(const sgx_exception_info_t *info, const void * args)
{
   (void)info;
   (void)args;
   is_out_of_enclave = true;
}

int communicate_with_trusted_server(SSL* ssl, int& i, uint64_t& mean_tsc_0, uint64_t& mean_tsc_500, uint32_t& count, cond_buffer_t* b, int waiting_time = 500)
{
    unsigned char buf[200];
    int ret = 1;
    int error = 0;
    int len = 0;
    int bytes_written = 0;
    int bytes_read = 0;
    sgx_status_t status;

    long long calibration_start_tsc = 0;
    long long calibration_end_tsc = 0;

        readTSC(&calibration_start_tsc);
        //t_print("Start calibration tsc : %lld\n", calibration_start_tsc);
        if(i % 2 == 0){
            len = snprintf((char*)buf, sizeof(buf) - 1, CALIBRATION_ASK_0);
        }
        else {
            b->isCounting = 1;
            len = snprintf((char*)buf, sizeof(buf) - 1, CALIBRATION_ASK_TIME, waiting_time);
        }

        while ((bytes_written = SSL_write(ssl, buf, (size_t)len)) <= 0)
        {
            error = SSL_get_error(ssl, bytes_written);
            if (error == SSL_ERROR_WANT_WRITE)
                continue;
            //t_print(TLS_CLIENT "Failed! SSL_write returned %d\n", error);
            if (bytes_written == 0) ret = -1;
            else ret = bytes_written;
            goto done;
        }

        do
            {
                len = sizeof(buf) - 1;
                memset(buf, 0, sizeof(buf));
                bytes_read = SSL_read(ssl, buf, (size_t)len);
                if (bytes_read <= 0)
                {
                    int error = SSL_get_error(ssl, bytes_read);
                    if (error == SSL_ERROR_WANT_READ)
                        continue;

                    t_print(TLS_CLIENT "Failed! SSL_read returned error=%d\n", error);
                    if (bytes_read == 0) ret = -1;
                    else ret = bytes_read;
                    break;
                }
                b->isCounting = 0;
                readTSC(&calibration_end_tsc);
                if(i % 2 == 0){
                    //t_print("time elapsed no delay: %lld\n", calibration_end_tsc - calibration_start_tsc);
                    mean_tsc_0 += calibration_end_tsc - calibration_start_tsc;
                }
                else{
                    //t_print("time elapsed with delay: %lld\n", calibration_end_tsc - calibration_start_tsc);
                    mean_tsc_500 += calibration_end_tsc - calibration_start_tsc;
                    count += b->count;
                }
                //server_time = extract_server_time((const char*) buf);
                ret = 0;
                goto done;
            } while (1);
    done:
        return ret;
    }


int launch_tls_client_with_trusted_server(const char* server_name,const char* server_port, int& i, uint32_t& count,
    uint64_t& mean_tsc_0, uint64_t& mean_tsc_500, cond_buffer_t *b, int waiting_time){
    //t_print(TLS_CLIENT " Connecting to trusted server...\n");

    int ret = 0;

    SSL_CTX* ssl_client_ctx = nullptr;
    SSL* ssl_session = nullptr;

    X509* cert = nullptr;
    EVP_PKEY* pkey = nullptr;
    SSL_CONF_CTX* ssl_confctx = SSL_CONF_CTX_new();

    int client_socket = -1;
    int error = 0;

    //t_print("\nStarting" TLS_CLIENT "\n\n\n");

    if ((ssl_client_ctx = SSL_CTX_new(TLS_client_method())) == nullptr)
    {
        t_print(TLS_CLIENT "unable to create a new SSL context\n");
        goto done;
    }

    if (initalize_ssl_context(ssl_confctx, ssl_client_ctx) != SGX_SUCCESS)
    {
        t_print(TLS_CLIENT "unable to create a initialize SSL context\n ");
        goto done;
    }

    // specify the verify_callback for custom verification
    SSL_CTX_set_verify(ssl_client_ctx, SSL_VERIFY_PEER, &verify_callback);
    //t_print(TLS_CLIENT "load cert and key\n");
    if (load_tls_certificates_and_keys(ssl_client_ctx, cert, pkey) != 0)
    {
        t_print(TLS_CLIENT
               " unable to load certificate and private key on the client\n");
        goto done;
    }

    if ((ssl_session = SSL_new(ssl_client_ctx)) == nullptr)
    {
        t_print(TLS_CLIENT
               "Unable to create a new SSL connection state object\n");
        goto done;
    }

    //t_print(TLS_CLIENT "new ssl connection getting created\n");
    client_socket = create_socket(server_name, server_port);
    if (client_socket == -1)
    {
        t_print(
            TLS_CLIENT
            "create a socket and initiate a TCP connect to server: %s:%s "
            "(errno=%d)\n",
            server_name,
            server_port,
            errno);
        goto done;
    }

    // set up ssl socket and initiate TLS connection with TLS server
    SSL_set_fd(ssl_session, client_socket);

    if ((error = SSL_connect(ssl_session)) != 1)
    {
        t_print(
            TLS_CLIENT "Error: Could not establish a TLS session ret2=%d "
                       "SSL_get_error()=%d\n",
            error,
            SSL_get_error(ssl_session, error));
        goto done;
    }
    //t_print(TLS_CLIENT "successfully established TLS channel:%s\n",
        //SSL_get_version(ssl_session));

        if ((error = communicate_with_trusted_server(ssl_session, i, mean_tsc_0, mean_tsc_500, count ,b, waiting_time)) !=0)//, ts)) != 0)
        {
            t_print(TLS_CLIENT "Failed: communicate_with_trusted_server (ret=%d)\n", error);
            goto done;
        }


    
    // Free the structures we don't need anymore
    ret = 0;
done:

    if (client_socket != -1) 
    {
        ocall_close(&ret, client_socket);
        if (ret != 0)
            t_print(TLS_CLIENT "OCALL: error close socket\n");
    }

    if (ssl_session)
    {
        SSL_shutdown(ssl_session);
        SSL_free(ssl_session);
    }

    if (cert)
        X509_free(cert);

    if (pkey)
        EVP_PKEY_free(pkey);

    if (ssl_client_ctx)
        SSL_CTX_free(ssl_client_ctx);

    if (ssl_confctx)
        SSL_CONF_CTX_free(ssl_confctx);

    //t_print(TLS_CLIENT " %s\n", (ret == 0) ? "success" : "failed");
    return (ret);
}



server_connection server_connections[MAX_SERVERS];

int communicate_with_server(server_connection *conn, char *msg, long long *rsp) {
    unsigned char buf[200];
    int len, bytes_written, bytes_read;
    int error;

    len = snprintf((char*)buf, sizeof(buf) - 1, TIMESTAMPS_ASK, msg);

    while ((bytes_written = SSL_write(conn->ssl_session, buf, (size_t)len)) <= 0) {
        error = SSL_get_error(conn->ssl_session, bytes_written);
        if (error == SSL_ERROR_WANT_WRITE) continue;
        t_print("SSL_write failed: %d\n", error);
        return -1;
    }

    do {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        bytes_read = SSL_read(conn->ssl_session, buf, (size_t)len);
        if (bytes_read <= 0) {
            error = SSL_get_error(conn->ssl_session, bytes_read);
            if (error == SSL_ERROR_WANT_READ) continue;
            t_print("SSL_read failed: %d\n", error);
            return -1;
        }
        *rsp = extract_ts((const char*)buf);
        return 0;
    } while (1);

    return 0;
}


/*
void askTS() {
    t_print("Asking TS\n");
    cond_runtime_t *r = &runtime_scheduler;
    long long response = 0;
    char message[100];
    char client_response[100];
    launch_tls_client2((const char*) "localhost", (const char *) "12345", message, &response);
    sgx_thread_mutex_lock(&r->mutex);
    sgx_thread_cond_wait(&r->startRuntime, &r->mutex);

    //while (1) {
    while (!r->isAsking) {
        sgx_thread_cond_wait(&r->startAsking, &r->mutex);
    }
    r->isAsking = 0;
    snprintf(message, sizeof(message), "%lld", timestamps);
    t_print("Message : %s\n", message);
    launch_tls_client2((const char*) "localhost", (const char *) "12345", message, &response);

    snprintf(client_response, sizeof(client_response), "%lld", response);
    write_to_session_peer(r->ssl_session, (char*)&client_response, sizeof(client_response));
    r->pendingDemand = 1;
        sgx_thread_cond_signal(&r->demandPending);
    //}

    sgx_thread_mutex_unlock(&r->mutex);
}
*/
/*
void readTS(){
    cond_runtime_t *r = &runtime_scheduler;
    //sgx_thread_mutex_lock(&r->mutex);
    sgx_thread_cond_wait(&r->startRuntime, &r->mutex);
    while(1){
        sgx_thread_cond_wait(&r->startReading, &r->mutex);
            readTSC(&timestamps);
            //t_print("Timestamps : %lld\n", timestamps);
            //r->isReading = 0;
    }
    sgx_thread_mutex_unlock(&r->mutex);
    //sgx_unregister_aex_handler(my_aex_notify_handler);

}*/

int handle_communication_until_done(
    int& server_socket_fd,
    int& client_socket_fd,
    SSL_CTX*& ssl_server_ctx,
    SSL*& ssl_session,
    bool keep_server_up,
    cond_runtime_t *r)
{
    int ret = -1;
    int  test_error = 1;
    int code_val;
    int count = 0;
    sgx_status_t status; 
    long long former_aex_number = 0;

    do {
        struct sockaddr_in addr;
        uint len = sizeof(addr);

        // reset ssl_session and client_socket_fd to prepare for the new TLS
        // connection
        if (client_socket_fd > 0)
        {
            ocall_close(&ret, client_socket_fd);
            if (ret != 0) {
                t_print(TLS_SERVER "OCALL: error closing client socket before starting a new TLS session.\n");
                continue;
            }
        }


        SSL_free(ssl_session);
        //t_print(TLS_SERVER " ===== waiting for client connection =====\n");
        client_socket_fd = accept(server_socket_fd, (struct sockaddr*)&addr, &len);
        if (client_socket_fd < 0) {
            t_print(TLS_SERVER "Unable to accept the client request\n");
            continue;
        }

        t_print(TLS_SERVER "Client connected, socket: %d\n", client_socket_fd);


        if ((ssl_session = SSL_new(ssl_server_ctx)) == nullptr) {
            t_print(TLS_SERVER "Unable to create a new SSL connection state object\n");
            continue;
        }

        SSL_set_fd(ssl_session, client_socket_fd);
        test_error = SSL_accept(ssl_session);
        if (test_error <= 0) {
            t_print(TLS_SERVER "SSL handshake failed, error(%d)(%d)\n", test_error, SSL_get_error(ssl_session, test_error));
            continue;
        }
        code_val = read_from_session_peer_tsc(ssl_session, count);
        if (code_val == 10) {
            t_print("former_count : %lld\n", former_aex_number);
            //t_print("aex_count - former coutn : %lld\n", aex_count - former_aex_number);
            /*
            if((aex_count - former_aex_number) <= 2) {
                t_print(TLS_SERVER "Answer directly: %lld\n", aex_count - former_aex_number);     
                former_aex_number = aex_count;
                char response[SERVER_PAYLOAD_SIZE];
                snprintf(response, sizeof(response), "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<h2>Timestamps</h2>\r\n<p>%lld</p>\r\n", timestamps);

                if (write_to_session_peer(ssl_session, response, strlen(response)) != 0) {
                    t_print(TLS_SERVER "Write to client failed\n");
                    continue;
                    
                } 
            }
            else if ((aex_count - former_aex_number) > 2) {
                t_print("test\n");
                former_aex_number = aex_count;
                t_print(TLS_SERVER "AEX count: %lld\n", aex_count);
                is_out_of_enclave = false;
                sgx_thread_mutex_lock(&r->mutex);
                r->isAsking = 1;
                r->ssl_session = ssl_session;
                sgx_thread_cond_signal(&r->startAsking);
                while(r->pendingDemand == 0) {
                    sgx_thread_cond_wait(&r->demandPending, &r->mutex);
                }
                r->pendingDemand = 0;
                sgx_thread_mutex_unlock(&r->mutex);
            }
        */  
        }
        if (code_val != 10 && code_val != 0)
        {
            t_print(TLS_SERVER " Read from client failed\n");
            break;
        }
        ret = 0;
         
    }
    while (1);//keep_server_up);
    return ret;
}


int handle_communication_until_done2(
    int& server_socket_fd,
    int& client_socket_fd,
    SSL_CTX*& ssl_server_ctx,
    SSL*& ssl_session,
    bool keep_server_up,
    cond_runtime_t *r)
{   

    struct sockaddr_in addr;
    uint len = sizeof(addr);

    int ret = -1;
    int  test_error = 1;
    int code_val;
    int count = 0;
    int max_fd = 0;
    sgx_status_t status; 
    long long former_aex_number = 0;

    int sel;
    fd_set read_flags, write_flags;
    struct timeval waitd = {5, 0};

    int client_sockets[MAX_CLIENTS];
    SSL *ssl[MAX_CLIENTS];
    int num_clients = 0;

    // Initialize client_sockets and ssl arrays
    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_sockets[i] = -1;
        ssl[i] = NULL;
    }
    SSL_CTX *ctx = ssl_server_ctx;
    


    //connection to trusted server

    if (client_socket_fd > 0)
    {
        ocall_close(&ret, client_socket_fd);
        if (ret != 0) {
            t_print(TLS_SERVER "OCALL: error closing client socket before starting a new TLS session.\n");
        }
    }
    SSL_free(ssl_session);

    while(1){

        FD_ZERO(&read_flags);
        FD_ZERO(&write_flags);

        FD_SET(server_socket_fd, &read_flags);
        max_fd = server_socket_fd;

        /*
        test_error = SSL_accept(ssl_session);
        if (test_error <= 0) {
            t_print(TLS_SERVER "SSL handshake failed, error(%d)(%d)\n", test_error, SSL_get_error(ssl_session, test_error));
            continue;
        }
        SSL_set_fd(ssl_session, client_socket_fd);
        */


        for(int i = 0; i < MAX_CLIENTS; i++){
            if(client_sockets[i] > 0){
                FD_SET(client_sockets[i], &read_flags);
                FD_SET(client_sockets[i], &write_flags);
                if(client_sockets[i] > max_fd)
                    max_fd = client_sockets[i];
            }
        }

        int osef = max_fd + 1;
        //sel = ocall_select(&sel, &osef, &read_flags, &write_flags, (fd_set*)0, &waitd);
        //sel =ocall_select(&sel, osef, &read_flags, &write_flags, &waitd);
        if(sel < 0) {
            t_print(TLS_SERVER "Select error\n");
        }

        if(FD_ISSET(server_socket_fd, &read_flags)){
            client_socket_fd = accept(server_socket_fd, (struct sockaddr*)&addr, &len);
            if(client_socket_fd<0){
                t_print(TLS_SERVER "Unable to accept the client request\n");
            }

                
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (client_sockets[i] == -1) {
                    client_sockets[i] = client_socket_fd;
                    num_clients++;
                    t_print("New client connected: %d\n", client_socket_fd);
                    ssl[i] = SSL_new(ctx);
                    SSL_set_fd(ssl[i], client_socket_fd);
                    if (SSL_accept(ssl[i]) <= 0) {
                        t_print(TLS_SERVER "SSL handshake failed\n");
                        ocall_close(&ret, client_socket_fd);
                        SSL_free(ssl[i]);
                        ssl[i] = NULL;
                        client_sockets[i] = -1;
                        num_clients--;
                    }
                    break;
                }
            }
        }

        //check for activity on client sockets
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (client_sockets[i] == -1 || ssl[i] == NULL) continue;
            if (FD_ISSET(client_sockets[i], &read_flags)) {
                t_print("read\n");
                code_val = read_from_session_peer_tsc(ssl[i], count);
                if (code_val == 10) {
                    t_print(TLS_SERVER "Socket ready for writing\n");
                    //FD_CLR(client_socket_fd, &write_flags);
                    if(1){//(aex_count - former_aex_number) <= 2) {
                        //t_print(TLS_SERVER "Answer directly: %lld\n", aex_count - former_aex_number);     
                        //former_aex_number = aex_count;
                        char response[SERVER_PAYLOAD_SIZE];
                        snprintf(response, sizeof(response), "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<h2>Timestamps</h2>\r\n<p>%lld</p>\r\n", timestamps);

                        if (write_to_session_peer(ssl[i], response, strlen(response)) != 0) {
                            t_print(TLS_SERVER "Write to client failed\n");
                            continue;
                        } 
                        
                    }
                    /*
                    else if ((aex_count - former_aex_number) > 2) {
                        t_print("test\n");
                        former_aex_number = aex_count;
                        t_print(TLS_SERVER "AEX count: %lld\n", aex_count);
                        is_out_of_enclave = false;
                        sgx_thread_mutex_lock(&r->mutex);
                        r->isAsking = 1;
                        r->ssl_session = ssl_session;
                        sgx_thread_cond_signal(&r->startAsking);
                        while(r->pendingDemand == 0) {
                            sgx_thread_cond_wait(&r->demandPending, &r->mutex);
                        }
                        r->pendingDemand = 0;
                        sgx_thread_mutex_unlock(&r->mutex);
                    }
                    */
                    FD_CLR(client_sockets[i], &write_flags);
                }
                if (code_val != 10 && code_val != 0)
                {
                    t_print(TLS_SERVER " Read from client failed\n");
                    break;
                }
                ret = 0;
            }
            else if(FD_ISSET(client_sockets[i], &write_flags)) {
                t_print(TLS_SERVER "Socket ready for reading\n");
                code_val = read_from_session_peer_tsc(ssl[i], count);
                FD_CLR(client_sockets[i], &read_flags);
            } 
            else {
                t_print("nothing\n");
            }

        }
    }

    /*
    t_print(TLS_SERVER "Client connected, socket: %d\n", client_socket_fd);

    SSL_set_fd(ssl_session, client_socket_fd);
    test_error = SSL_accept(ssl_session);
    if (test_error <= 0) {
        t_print(TLS_SERVER "SSL handshake failed, error(%d)(%d)\n", test_error, SSL_get_error(ssl_session, test_error));
    }
    */
    return ret;
}
/*
int set_up_tls_server(const char* server_port, int keep_server_up)
{
    cond_runtime_t *r = &runtime_scheduler; 
    int ret = 0;
    int server_socket_fd;
    int client_socket_fd = -1;
    unsigned int server_port_number;

    X509* certificate = nullptr;
    EVP_PKEY* pkey = nullptr;
    SSL_CONF_CTX* ssl_confctx = SSL_CONF_CTX_new();

    SSL_CTX* ssl_server_ctx = nullptr;
    SSL* ssl_session = nullptr;
    

    //const char* args = NULL; 
    //sgx_aex_mitigation_node_t node;
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
    
    server_port_number = (unsigned int)atoi(server_port); // convert to char* to int
    //if (create_listener_socket(server_port_number, server_socket_fd) != 0)
    //{
    //    t_print(TLS_SERVER " unable to create listener socket on the server\n ");
    //    goto exit;
    //}

    //sgx_register_aex_handler(&node, my_aex_notify_handler, (const void*)args);

    // handle communication
    sgx_thread_mutex_lock(&r->mutex);
    r->runtimeStart = 1;
    r->isReading = 1;
    sgx_thread_cond_signal(&r->startRuntime);
    sgx_thread_cond_signal(&r->startReading);
    sgx_thread_mutex_unlock(&r->mutex);

    while(1){}
    //while(1){
    /*
        ret = handle_communication_until_done2(
            server_socket_fd,
            client_socket_fd,
            ssl_server_ctx,
            ssl_session,
            keep_server_up,
            r);
        //t_print("sortie de handle_communication_until_done\n");
        if (ret != 0)
        {
            t_print(TLS_SERVER "server communication error %d\n", ret);
            goto exit;
        }
    //}
    

exit:
    //sgx_unregister_aex_handler(my_aex_notify_handler);
    ocall_close(&ret, client_socket_fd); // close the socket connections
    if (ret != 0)
        t_print(TLS_SERVER "OCALL: error closing client socket\n");
    ocall_close(&ret, server_socket_fd);
    if (ret != 0)
        t_print(TLS_SERVER "OCALL: error closing server socket\n");

    if (ssl_session)
    {
        SSL_shutdown(ssl_session);
        SSL_free(ssl_session);
    }
    if (ssl_server_ctx)
        SSL_CTX_free(ssl_server_ctx);
    if (ssl_confctx)
        SSL_CONF_CTX_free(ssl_confctx);
    if (certificate)
        X509_free(certificate);
    if (pkey)
        EVP_PKEY_free(pkey);
    return (ret);
}

*/