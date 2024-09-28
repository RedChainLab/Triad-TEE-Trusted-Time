#include <unistd.h>

#include "App/Node.h"

int main(int argc, char* argv[]) {
    if (argc < 2 || argc % 2 != 0) {
        std::cerr << "Usage: " << argv[0] << " <port> [<hostname> <port> ...]" << std::endl;
        return -1;
    }

    uint16_t port = atoi(argv[1]);
    Node* node = Node::get_instance(port);
    Node* node2 = Node::get_instance(port+1);
    Node::get_instance(port);
    node->get_timestamp();

    usleep(10000);
    node->add_sibling("127.0.0.1", port+1);

    std::cout << "<Enter anything to continue>"<< std::endl;
    std::string msg;
    std::cin >> msg;

    for (int i = 2; i < argc; i += 2) {
        node->add_sibling(argv[i], atoi(argv[i+1]));
        node2->add_sibling(argv[i], atoi(argv[i+1]));
    }

    std::cout << "<Enter anything to continue>"<< std::endl;
    std::cin >> msg;

    Node::destroy_instance(port);
    Node::destroy_instance(port);
    Node::destroy_instance(port+1);
    return 0;
}