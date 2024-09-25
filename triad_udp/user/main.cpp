#include <iostream>

#include "App/App.h"

int main(int argc, char* argv[]) {
    uint16_t port = 8080;
    Node* node = Node::get_instance(port);
    Node::get_instance(port);
    Node::destroy_instance();
    Node::destroy_instance();
    return 0;
}