#include <iostream>

#include "App/App.h"

int main(int argc, char* argv[]) {
    Node* node = Node::get_instance();
    Node::get_instance();
    Node::destroy_instance();
    Node::destroy_instance();
    return 0;
}