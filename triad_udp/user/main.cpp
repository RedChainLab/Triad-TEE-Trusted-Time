#include <unistd.h>

#include "App/App.h"

int main(int argc, char* argv[]) {
    if (argc < 2 || argc % 2 != 0) {
        std::cerr << "Usage: " << argv[0] << " <port> [<hostname> <port> ...]" << std::endl;
        return -1;
    }

    uint16_t port = atoi(argv[1]);
    Node* node = Node::get_instance(port);
    Node::get_instance(port);
    node->get_timestamp();

    for (int i = 2; i < argc; i += 2) {
        node->contactSibling(argv[i], atoi(argv[i+1]));
    }

    usleep(10000);

    node->printSiblings();

    std::string msg;
    std::cin >> msg;

    node->printSiblings();

    Node::destroy_instance(port);
    Node::destroy_instance(port+1);
    return 0;
}