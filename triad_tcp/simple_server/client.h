// client.h
#ifndef CLIENT_H
#define CLIENT_H

#include "common.h"

class Client {
public:
    const char* server_ip;
    int *port;
    //int dest[NB_NODE];
    sync_struct* sync;
    node_connection node_servers[NB_NODE];
    SSL_CTX* ctx;
    Client(const char* server_ip, int* port, sync_struct* s);
    ~Client();
    int run();

private:
    int create_socket(const char* server_ip, int port);
    void wait_in_enclave(int seconds);
    void establish_socket();
    SSL_CTX* init_client_ctx();

    int server_sock;
};
//void readTSC(long long* ts);
void generate_symmetric_key(unsigned char* key, int size);

#endif // CLIENT_H
