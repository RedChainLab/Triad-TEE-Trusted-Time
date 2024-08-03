#include "ssl_common.h"
#include "../parsing/parsing.h"

unsigned long inet_addr2(const char *str)
{
    unsigned long lHost = 0;
    char *pLong = (char *)&lHost;
    char *p = (char *)str;
    while (p)
    {
        *pLong++ = atoi(p);
        p = strchr(p, '.');
        if (p)
            ++p;
    }
    return lHost;
}


int create_socket(const char* server_name,const char* server_port)
{
    int sockfd = -1;
    struct sockaddr_in dest_sock;
    int res = -1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        t_print(TLS_CLIENT "Error: Cannot create socket %d.\n", errno);
        goto done;
    }


    dest_sock.sin_family = AF_INET;
    dest_sock.sin_port = htons(atoi(server_port));
    dest_sock.sin_addr.s_addr = inet_addr2(server_name);
    bzero(&(dest_sock.sin_zero), sizeof(dest_sock.sin_zero));
    
    if (connect(
                sockfd, (sockaddr*) &dest_sock,
                sizeof(struct sockaddr)) == -1)
    {
        t_print(
            TLS_CLIENT "failed to connect to %s:%s (errno=%d)\n",
            server_name,
            server_port,
            errno);
        ocall_close(&res, sockfd);
        if (res != 0)
            t_print(TLS_CLIENT "OCALL: error closing socket\n");
        sockfd = -1;
        goto done;
    }
    //t_print(TLS_CLIENT "connected to %s:%s\n", server_name, server_port);

done:
    return sockfd;
}

int create_listener_socket(int port, int& server_socket)
{
    int ret = -1;
    const int reuse = 1;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        t_print(TLS_SERVER "socket creation failed\n");
        goto exit;
    }

    if (setsockopt(
            server_socket,
            SOL_SOCKET,
            SO_REUSEADDR,
            (const void*)&reuse,
            sizeof(reuse)) < 0)
    {
        t_print(TLS_SERVER "setsocket failed \n");
        goto exit;
    }

    if (bind(server_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        t_print(TLS_SERVER "port : %d\n", port);
        t_print(TLS_SERVER "server_socket : %d\n", server_socket);
        t_print(TLS_SERVER "Unable to bind socket to the port\n");
        goto exit;
    }

    if (listen(server_socket, 20) < 0)
    {
        t_print(TLS_SERVER "Unable to open socket for listening\n");
        goto exit;
    }
    ret = 0;
exit:
    return ret;
}

/*
int launch_tls_client2(const char* server_name, const char* server_port, char* msg, long long* rsp){
    //t_print(TLS_CLIENT "====== called launch tls client ======\n");

    int ret = 0;

    SSL_CTX* ssl_client_ctx = nullptr;
    SSL* ssl_session = nullptr;

    X509* cert = nullptr;
    EVP_PKEY* pkey = nullptr;
    SSL_CONF_CTX* ssl_confctx = SSL_CONF_CTX_new();

    int client_socket = -1;
    int error = 0;

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
    // start the client server communication
    if ((error = communicate_with_server(ssl_session, msg, rsp)) !=0)//, ts)) != 0)
    {
        t_print(TLS_CLIENT "Failed: communicate_with_server (ret=%d)\n", error);
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
*/
/*
int communicate_with_server(SSL* ssl, char* msg, long long* rsp)
{
    unsigned char buf[200];
    int ret = 1;
    int error = 0;
    int len = 0;
    int bytes_written = 0;
    int bytes_read = 0;
    int count = 0;
    sgx_status_t status;

    // Write an GET request to the server
    //t_print(TLS_CLIENT "-----> Write to server test:\n");
    len = snprintf((char*)buf, sizeof(buf) - 1, TIMESTAMPS_ASK, msg);
    //t_print("ts_formated : %s\n", buf);
    while ((bytes_written = SSL_write(ssl, buf, (size_t)len)) <= 0)
    {
        error = SSL_get_error(ssl, bytes_written);
        if (error == SSL_ERROR_WANT_WRITE)
            continue;
        t_print(TLS_CLIENT "Failed! SSL_write returned %d\n", error);
        if (bytes_written == 0) ret = -1;
        else ret = bytes_written;
        goto done;
    }

    // Read the HTTP response from server
    //t_print(TLS_CLIENT "<---- Read from server:\n");
    
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
        //t_print(TLS_CLIENT "Message received test: %s\n", buf);
        *rsp = extract_ts((const char*) buf);
        ret = 0;
        goto done;
    } while (1);
done:
    return ret;
}
*/

/*
server_connection server_connections[MAX_SERVERS];



int establish_connections(SSL_CTX *ctx) {
    int ret;
    server_connections[0].server_name = "127.0.0.1";
    server_connections[0].server_port = "12341";
    for (int i = 0; i < 1;i++){//MAX_SERVERS; i++) {
        int sockfd = create_socket(server_connections[i].server_name, server_connections[i].server_port);
        if (sockfd == -1) {
            t_print("Failed to create socket for server %s:%s\n", "SERVER_NAME", "SERVER_PORT");
            ret = -1;
            continue;
        }

        server_connections[i].socket_fd = sockfd;
        server_connections[i].ssl_session = SSL_new(ctx);
        SSL_set_fd(server_connections[i].ssl_session, sockfd);

        if (SSL_connect(server_connections[i].ssl_session) != 1) {
            ocall_close(&ret, sockfd);
            SSL_free(server_connections[i].ssl_session);
            server_connections[i].ssl_session = NULL;
            server_connections[i].socket_fd = -1;
            ret = -1;
        }
    }
    return ret;
}



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


int handle_connections() {
    fd_set read_flags, write_flags;
    struct timeval timeout;
    long long rsp;
    int ret;
    while (1) {
        FD_ZERO(&read_flags);
        FD_ZERO(&write_flags);

        int max_fd = -1;
        for (int i = 0; i < MAX_SERVERS; i++) {
            if (server_connections[i].socket_fd > 0) {
                FD_SET(server_connections[i].socket_fd, &read_flags);
                FD_SET(server_connections[i].socket_fd, &write_flags);
                if (server_connections[i].socket_fd > max_fd) {
                    max_fd = server_connections[i].socket_fd;
                }
            }
        }

        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        int osef = max_fd + 1;
        int sel = ocall_select(&sel, &osef, &read_flags, &write_flags, (fd_set*)0, &timeout);//&waitd);

        if (sel < 0) {
            t_print("select error\n");
            ret = -1;
            continue;
        } else if (sel == 0) {
            t_print("Timeout, no file descriptors ready\n");
            continue;
        }

        for (int i = 0; i < MAX_SERVERS; i++) {
            if (server_connections[i].socket_fd > 0) {
                if (FD_ISSET(server_connections[i].socket_fd, &read_flags) || FD_ISSET(server_connections[i].socket_fd, &write_flags)) {
                    if (communicate_with_server(&server_connections[i], "MSG", &rsp) != 0) {
                        t_print("Communication with server %s:%s failed\n", "SERVER_NAME", "SERVER_PORT");
                        ocall_close(&ret, server_connections[i].socket_fd);
                        SSL_free(server_connections[i].ssl_session);
                        server_connections[i].ssl_session = NULL;
                        server_connections[i].socket_fd = -1;
                        ret = -1;
                    } else {
                        t_print("Received response: %lld\n", rsp);
                    }
                }
            }
        }
    }
    return ret;
}


int launch_tls_client2(const char* server_name, const char* server_port, char* msg, long long* rsp){
    int ret = 0;
    SSL_CTX* ssl_client_ctx = nullptr;
    SSL* ssl_session = nullptr;

    X509* cert = nullptr;
    EVP_PKEY* pkey = nullptr;
    SSL_CONF_CTX* ssl_confctx = SSL_CONF_CTX_new();

    int client_socket = -1;
    int error = 0;

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

    if(establish_connections(ssl_client_ctx)){
        t_print(TLS_CLIENT "Failed to establish connections\n");
        goto done;
    };
    if(handle_connections()){
        t_print(TLS_CLIENT "Failed to handle connections\n");
        goto done;
    };
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
*/