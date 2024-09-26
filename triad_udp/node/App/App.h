#ifndef NODE_H
#define NODE_H

#include <iostream>
#include <map>

#include <sgx_urts.h>
#include <sgx_uswitchless.h>

class Node {
public:
    static Node* get_instance(uint16_t port);
    static void destroy_instance(uint16_t port);
    int get_timestamp();
    void contactSibling(const char* hostname, uint16_t port);
    void printSiblings();
private:
    uint16_t port;
    int sock;
    std::map<std::pair<std::string, uint16_t>, int> siblings;

    Node(uint16_t _port);
    ~Node();
    int initialize_enclave(const sgx_uswitchless_config_t* us_config);
    bool setup_socket();
    void listen();
    static std::map<int, Node*> nodes;
    sgx_enclave_id_t enclave_id;
    static const char* ENCLAVE_FILE;
};

#endif // NODE_H