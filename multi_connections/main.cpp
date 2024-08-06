#include "server.h"
#include "client.h"
#include <iostream>
#include <thread>
#include <unistd.h>
#define PORT 12345
#define SERVER_IP "127.0.0.1"
#define NB_NODE 2



void start_server(int server_port) {
    Server server(server_port);
    server.run();
}

void start_client(int* node_port) {
    Client client(SERVER_IP, node_port);
    client.run();
}

int main(int argc, char** argv) {
    int node1_port = atoi(argv[1]);
    int node2_port = atoi(argv[2]);
    int server_port = atoi(argv[3]);

    int node_port[2] = {node1_port, node2_port};

    if (argc < 4) {
        std::cerr << "<node1_port>: " << argv[1] << "<node2_port>: " << argv[2] << " <server_port>" << argv[3] << std::endl;
        return 1;
    }
    std::thread server_thread(start_server, server_port);
    sleep(1); // Ensure server starts before client
    std::thread client_thread(start_client, node_port);

    server_thread.join();
    client_thread.join();

    return 0;
}
