#include <unistd.h>

#include "App/Node.h"

int main(int argc, char* argv[]) {
    if (argc < 2 || argc % 2 != 0) {
        std::cerr << "Usage: " << argv[0] << " <port> [<hostname> <port> ...]" << std::endl;
        return -1;
    }

    uint16_t port = atoi(argv[1]);
    Node* node = Node::get_instance(port);
    Node::get_instance(port);
    node->get_timestamp();

    usleep(10000);
    std::cout << "<Enter anything to continue>"<< std::endl;
    std::string msg;
    std::cin >> msg;
    Node::destroy_instance(port);
    Node::destroy_instance(port);
    return 0;
}