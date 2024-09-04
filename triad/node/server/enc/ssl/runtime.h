#ifndef RUNTIME_H
#define RUNTIME_H

#include "ssl_common.h"
#include "../client_class.h"
#include "../server_class.h"


void init_client(const char* server_ip, int node_port1, int node_port2, int client_port, int trusted_server_port);
void init_server(int port, int node_port1, int node_port2, int client_port, int trusted_server_port);
void readTS();

#endif // RUNTIME_H