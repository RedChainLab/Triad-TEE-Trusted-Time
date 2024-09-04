// client.h
#ifndef CLIENT_H
#define CLIENT_H

#include "../enc/ssl/ssl_common.h"

class Client {
public:
    cond_runtime_t* runtime_scheduler;
    const char* server_ip;
    int *port;
    int own_port;
    bool *out_enclave;
    node_connection node_connections[NB_NODE+NB_CLIENT+NB_SERVER]; //à mettre en private
    
    Client(const char* server_ip, int own_port, int* port, cond_runtime_t* rs, bool* out_enc);
    ~Client();
    int run();

private:
    SSL_CTX* ctx;
    int create_socket(const char* server_ip, int port);
    void wait_in_enclave(int seconds);
    void establish_socket();
    SSL_CTX* init_client_ctx();    
    int calibrate();
    long long add_opp_in_2ms = 0;
    long long drift_rate = 0;
    int waiting_time = 500;

    int server_sock;
};
void generate_symmetric_key(unsigned char* key, int size);

#endif // CLIENT_H
