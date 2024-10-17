#include <unistd.h>

#include "App/Node.h"

int main(int argc, char* argv[]) {
    if (argc < 3 || argc % 2 != 1) {
        std::cerr << "Usage: " << argv[0] << " <port> <core_rdTSC> [<hostname> <port> ...]" << std::endl;
        return -1;
    }

    uint16_t port = atoi(argv[1]);
    int core_rdTSC = atoi(argv[2]);
    Node* node = Node::get_instance(port, core_rdTSC);
    Node* node2 = Node::get_instance(port+1, core_rdTSC+1);
    Node* node3 = Node::get_instance(port+2, core_rdTSC+2);

    usleep(10000);
    node->add_sibling("127.0.0.1", port+1);
    node->add_sibling("127.0.0.1", port+2);
    node2->add_sibling("127.0.0.1", port+2);

    std::cout << "<Enter anything to continue>"<< std::endl;
    std::string msg;
    std::cin >> msg;

    node->poll_timestamp(-1);
    node2->poll_timestamp(-1);
    node3->poll_timestamp(-1);

    std::cout << "<Enter anything to continue>"<< std::endl;
    std::cin >> msg;

    Node::destroy_instance(port);
    Node::destroy_instance(port+1);
    Node::destroy_instance(port+2);
    return 0;
}