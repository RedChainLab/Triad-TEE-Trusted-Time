#ifndef SERVER_H
#define SERVER_H

#include "../enc/ssl/ssl_common.h"


class Server {
public:
    cond_runtime_t* runtime_scheduler;
    int port;
    Server(int port, int* node_port, cond_runtime_t* rs);
    ~Server();
    void run();

private:
    int create_socket(int p);
    SSL_CTX* init_server_ctx();
    void handle_client(node_connection &client);//, int client_port);



    int server_sock;
    SSL_CTX* ctx;
    node_connection clients[NB_NODE+NB_CLIENT+NB_SERVER];
};


#endif // SERVER_H
