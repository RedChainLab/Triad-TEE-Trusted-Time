#ifndef NODE_H
#define NODE_H

#include <iostream>
#include <sgx_urts.h>
#include <sgx_uswitchless.h>

class Node {
public:
    static Node* get_instance();
    static void destroy_instance();
    void set_value(int val);
    int get_value() const;

private:
    Node();
    ~Node();
    int initialize_enclave(const sgx_uswitchless_config_t* us_config);
    static Node* node;
    sgx_enclave_id_t enclave_id;
    static const char* ENCLAVE_FILE;
};

#endif // NODE_H