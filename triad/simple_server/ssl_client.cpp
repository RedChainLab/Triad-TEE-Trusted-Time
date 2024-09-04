#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 12300

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    // Here you could add CA certificates using SSL_CTX_load_verify_locations if necessary
}

int communicate_with_triad(
    SSL*& ssl_session,
    const char* payload,
    size_t payload_length)
{
    int bytes_written = 0;
    int ret = 0;
    unsigned char buf[200];

    while ((bytes_written = SSL_write(ssl_session, payload, payload_length)) <=
           0)
    {
        int error = SSL_get_error(ssl_session, bytes_written);
        if (error == SSL_ERROR_WANT_WRITE)
            continue;
        printf("Failed! SSL_write returned %d\n", error);
        ret = bytes_written;
        goto exit;
    }
    printf("%lu bytes written to session peer\n\n", payload_length);
    printf("<---- Read from server:\n");
    do
    {
        int len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        printf("len : %d\n", len);
        int bytes_read = SSL_read(ssl_session, buf, (size_t)len);
        if (bytes_read <= 0)
        {
            int error = SSL_get_error(ssl_session, bytes_read);
            if (error == SSL_ERROR_WANT_READ)
                continue;

            printf("Failed! SSL_read returned error=%d\n", error);
            if (bytes_read == 0) ret = -1;
            else ret = bytes_read;
            break;
        }
        printf(" %d bytes read\n", bytes_read);
        printf("Message received : %s\n", buf);
        //timestamps = extract_ts((const char*) buf);
        ret = 0;
        goto exit;
    } while (1);
    exit:
        return ret;
}

int main() {

    initialize_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));


    if (connect(server, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to connect");
        exit(EXIT_FAILURE);
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("Client asking for a timestamp---->\n");
        communicate_with_triad(ssl, "GET /timestamps HTTP/1.0\r\n",30);
        //communicate_with_triad(ssl, "GET /timestamps HTTP/1.0\r\n",30);

    }

    SSL_free(ssl);
    close(server);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return EXIT_SUCCESS;
}
