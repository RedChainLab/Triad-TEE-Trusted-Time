#include "server.h"
#include "client.h"
#include <iostream>
#include <thread>
#include <unistd.h>
#include "common.h"
#define SERVER_IP "127.0.0.1"


sync_struct syn ;


//int destination[NB_NODE] = {-1};


void start_server(int server_port) {
    Server server(server_port, &syn);
    server.run();
}

void start_client(int* node_port) {
    Client client(SERVER_IP, node_port, &syn);
    client.run();
}

int main(int argc, char** argv) {
    int own_port = atoi(argv[1]);

    int node1_port = atoi(argv[2]);
    int node2_port = atoi(argv[3]);
    int node3_port = atoi(argv[4]);


    int node_port[3] = {node1_port, node2_port, node3_port};

    if (argc < 5) {
        std::cerr << "<node1_port>: " << argv[1] << "<node2_port>: " << argv[2] << " <server_port>" << argv[3] << std::endl;
        return 1;
    }
    std::thread server_thread(start_server, own_port);
    sleep(1); // Ensure server starts before client
    std::thread client_thread(start_client, node_port);

    server_thread.join();
    client_thread.join();

    return 0;
}
