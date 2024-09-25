#ifndef NODE_H
#define NODE_H

#include <iostream>
#include <sgx_urts.h>
#include <sgx_uswitchless.h>

class Node {
public:
    static Node* get_instance(uint16_t port);
    static void destroy_instance();
    int get_timestamp();

private:
    uint16_t port;
    Node(uint16_t _port);
    ~Node();
    int initialize_enclave(const sgx_uswitchless_config_t* us_config);
    int setup_sockets();
    int setup_server_socket();
    int setup_client_socket();
    static Node* node;
    sgx_enclave_id_t enclave_id;
    static const char* ENCLAVE_FILE;
};

#endif // NODE_H