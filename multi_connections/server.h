#ifndef SERVER_H
#define SERVER_H

#include "common.h"


class Server {
public:
    int port;
    Server(int p);
    ~Server();
    void run();

private:
    int create_socket(int p);
    SSL_CTX* init_server_ctx();
    void load_certificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile);
    void handle_client(node_connection &client, int i);//, int client_port);

    int server_sock;
    SSL_CTX* ctx;
    node_connection clients[NB_NODE];
};


#endif // SERVER_H
