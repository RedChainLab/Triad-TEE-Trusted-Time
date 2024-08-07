#include "runtime.h"

bool out_enc = false;

static cond_runtime_t runtime_scheduler = {NULL, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, {0,0,0,0}, //{0,0},
                                            SGX_THREAD_MUTEX_INITIALIZER};

static void my_aex_notify_handler(const sgx_exception_info_t *info, const void * args)
{
    cond_runtime_t *r = &runtime_scheduler;
   (void)info;
   (void)args;
   r->nb_aex++;
    out_enc = true;
}

void count_add(void){
    cond_runtime_t *r = &runtime_scheduler;
    while(1){
        if(r->isCounting == 1){
            r->count++;
        }
    }
}



void init_client(const char* server_ip, int own_port, int node_port1, int node_port2, int client_port, int trusted_server_port){
    t_print("Connecting client to port %d and %d\n", node_port1, node_port2);
    int port[4] = {node_port1, node_port2, client_port, trusted_server_port};
    Client client(server_ip, own_port, port,  &runtime_scheduler, &out_enc);
    client.run();
}

void init_server(int port, int node_port1, int node_port2, int client_port, int trusted_server_port){
    t_print("Initializing server with port %d\n", port);
    int node_port[4] = {node_port1, node_port2, client_port, trusted_server_port};
    Server server(port, node_port, &runtime_scheduler);
    server.run();
}

void readTS(){
    const char* args = NULL; 
    sgx_aex_mitigation_node_t node;
    cond_runtime_t *r = &runtime_scheduler;
    sgx_register_aex_handler(&node, my_aex_notify_handler, (const void*)args);
    while(1){
        sgx_thread_mutex_lock(&r->mutex);
        out_enc = false;
        readTSC(&r->timestamps);
        r->timestamps += r->epoch;
        sgx_thread_mutex_unlock(&r->mutex);
    }
    sgx_unregister_aex_handler(my_aex_notify_handler);
}
