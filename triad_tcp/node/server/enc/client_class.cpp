#include "client_class.h"
#include <iostream>
#include <unistd.h>


#define RETRY_INTERVAL 2 // Retry interval in seconds


Client::Client(const char* server_ip, int op, int* port, cond_runtime_t* rs, bool *out_enc) : own_port(op), out_enclave(out_enc) {
    /*
    In : server_ip : IP address of the server
         port : port number of the server
         rs : runtime scheduler
    Out : Client object
    Description : Constructor of the Client class
    */
    ctx = init_client_ctx();
    if(!ctx){
        t_print("CLIENT : Unable to create SSL context\n");
        return;
    }
    runtime_scheduler = rs;
    for(int i = 0; i < NB_TOTAL; i++){
        node_connections[i].node_name = server_ip;
        node_connections[i].node_port = port[i];
        node_connections[i].socket_fd = -1;
        node_connections[i].ssl_session = nullptr;
        node_connections[i].is_connected = 0;
    }
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

Client::~Client() {
    /*
    In : void
    Out : void
    Description : Destructor of the Client class
    */
    int ret;
    ocall_close(&ret, server_sock);
    for(int i = 0; i < NB_TOTAL; i++){
        ocall_close(&ret, node_connections[i].socket_fd);
        SSL_free(node_connections[i].ssl_session);
    }
    EVP_cleanup();
}

void Client::wait_in_enclave(int seconds) {
    /*
    In : int seconds : number of seconds to wait (shorter time in reality)
    Out : void
    Description : Wait for a certain amount of time in the enclave
    */
    for (int j = 0; j < 25*seconds; j++){
        for(int i = 0; i < 10000000; i++){
        }
    }
}

int Client::create_socket(const char* server_ip, int port) {
    /*
    In : const char* server_ip : IP address of the node
         int port : port number of the node
    Out: ERROR_RETURN if the socket could not be created, the socket file descriptor otherwise
    Description : Create a socket and connect to the node
    */
    int sock;
    int ret;
    struct sockaddr_in addr;
    //sock = socket(AF_INET, SOCK_DGRAM, 0);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        t_print("Unable to create socket");
        return ERROR_RETURN;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr2(server_ip);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        ocall_close(&ret, sock);
        wait_in_enclave(RETRY_INTERVAL); // Wait before retrying
    } else {
        return sock;
    }
    return ERROR_RETURN;
}

SSL_CTX* Client::init_client_ctx() {
    /*
    In : void
    Out : SSL_CTX* : SSL context
    Description : Initialize the SSL context for the client
    */
    const SSL_METHOD* method;

    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        t_print("CLIENT : Unable to create a new SSL context\n");
        return NULL;
    }
    return ctx;
}

void Client::establish_socket() {
    /*
    In : void
    Out : void
    Description : Establish a socket connection with the node
    */
    int ret;
    //if the node is not calibrated, we only connect to the trusted server
    if(runtime_scheduler->isCalibrating == 1){
        if(node_connections[NB_TOTAL-1].socket_fd == -1){
            int sockfd = create_socket(node_connections[NB_TOTAL-1].node_name, node_connections[NB_TOTAL-1].node_port);
            if (sockfd == -1) {
                return;
            }  
            else{         
                node_connections[NB_TOTAL-1].socket_fd = sockfd;
                if((node_connections[NB_TOTAL-1].ssl_session = SSL_new(ctx)) == nullptr){
                    t_print("SERVER : Unable to create SSL session\n");
                    return;
                }
                SSL_set_fd(node_connections[NB_TOTAL-1].ssl_session, sockfd);
                ret = SSL_connect(node_connections[NB_TOTAL-1].ssl_session);// --> bloquant 
                if (ret != 1) {
                    t_print("SSL_connect failed\n");
                    ocall_close(&ret, sockfd);
                    SSL_free(node_connections[NB_TOTAL-1].ssl_session);
                    node_connections[NB_TOTAL-1].ssl_session = NULL;
                    node_connections[NB_TOTAL-1].socket_fd = -1;
                }
                else{
                    t_print("CLIENT : Connection established with server %s:%d\n", node_connections[NB_TOTAL-1].node_name, node_connections[NB_TOTAL-1].node_port);
                }
            }
        }
    }
    
    //if the node is calibrated, we connect to all the nodes
    else{
        for (int i = 0; i < NB_TOTAL; i++) {
                if(node_connections[i].socket_fd == -1){
                    int sockfd = create_socket(node_connections[i].node_name, node_connections[i].node_port);
                    if (sockfd == -1) {
                        continue;
                    }    
                    else{         
                        node_connections[i].socket_fd = sockfd;
                        if((node_connections[i].ssl_session = SSL_new(ctx)) == nullptr){
                            t_print("SERVER : Unable to create SSL session\n");
                            continue;
                        }
                        SSL_set_fd(node_connections[i].ssl_session, sockfd);
                        ret = SSL_connect(node_connections[i].ssl_session);// --> bloquant 
                        if (ret != 1) {
                            t_print("SSL_connect failed\n");
                            ocall_close(&ret, sockfd);
                            SSL_free(node_connections[i].ssl_session);
                            node_connections[i].ssl_session = NULL;
                            node_connections[i].socket_fd = -1;
                        }
                        else{
                            t_print("CLIENT : Connection established with server %s:%d\n", node_connections[i].node_name, node_connections[i].node_port);
                        }
                }
            }
        }
    }
}


int Client::calibrate(){
    /*
    In : void
    Out : int : 0 if success, -1 if failure
    Description : Calibrate the node. The node sends a message to the trusted server and measures 
    the time it takes to receive the response. The message contains the time the trusted server has to wait before answering. 
    It allows the node to calculate the drift rate and the number of operations it can perform in 2ms. 
    These informations are then used to adjust the timestamps provided by node.
    Messages format : "c;<own_port>;<type>;<waiting_time>"
    */
    int ret = 0;
    
    long long calibration_start_tsc = 0;
    long long calibration_end_tsc = 0;
    long long mean_tsc_0 = 0;
    long long mean_tsc_500 = 0;
    long long count = 0;
    long long delay = 0;

    unsigned char plaintext[200];
    unsigned char ciphertext[128];
    int ciphertext_len = 0;
    int n = 4;
    int cold_start_message = n;
    int number_of_instant_responses = n;
    int number_of_delayed_responses = n;

    node_connection trusted_server = node_connections[NB_TOTAL-1];
    sgx_thread_mutex_lock(&runtime_scheduler->mutex);
    runtime_scheduler->canSend = NOT_DELAYED;
    sgx_thread_mutex_unlock(&runtime_scheduler->mutex);

    
    while(cold_start_message > 0){
        while(runtime_scheduler->canSend == WAIT){
            continue;
        }
        
        cold_start_message--;
        t_print("CLIENT : Sending cold start message\n");
        snprintf((char*)plaintext, sizeof(plaintext), "c;%d;%d;%d", own_port, CALIBRATION_COLD_START, 0);
        ciphertext_len = aes_encrypt(plaintext, strlen((char*)plaintext), node_connections[NB_TOTAL-1].key, node_connections[NB_TOTAL-1].iv, ciphertext);
        if (ciphertext_len == -1) {
            t_print("Encryption failed.\n");
            return ERROR_RETURN;
        }
        send_udp_packet(node_connections[NB_TOTAL-1], ciphertext, ciphertext_len);
        wait_in_enclave(1);
        sgx_thread_mutex_lock(&runtime_scheduler->mutex);
        runtime_scheduler->canSend = WAIT;
        sgx_thread_mutex_unlock(&runtime_scheduler->mutex);
    }

    sgx_thread_mutex_lock(&runtime_scheduler->mutex);
    runtime_scheduler->canSend = DELAYED;
    sgx_thread_mutex_unlock(&runtime_scheduler->mutex);
    
    while(number_of_delayed_responses > 0){
        t_print("CLIENT : number_of_instant_responses : %d\n", number_of_delayed_responses);
        //wait for the server side isntruction before sending a message
        while(runtime_scheduler->canSend == WAIT){
            continue;
        }
        //if the server side received the trusted server message, we measure the time it took to receive it
        calibration_end_tsc = runtime_scheduler->timestamps;
        if(runtime_scheduler->canSend == DELAYED){
            if(calibration_end_tsc-calibration_start_tsc > 0 && calibration_end_tsc-calibration_start_tsc < 1000000000000000){
                sgx_thread_mutex_lock(&runtime_scheduler->mutex);
                number_of_delayed_responses--;
                sgx_thread_mutex_unlock(&runtime_scheduler->mutex);
                mean_tsc_500 += calibration_end_tsc - calibration_start_tsc;
                t_print("CLIENT : 0 ms end-start : %lld\n", calibration_end_tsc-calibration_start_tsc);
            }
        }

        snprintf((char*)plaintext, sizeof(plaintext), "c;%d;%d;%d", own_port, DELAYED, waiting_time);
        ciphertext_len = aes_encrypt(plaintext, strlen((char*)plaintext), node_connections[NB_TOTAL-1].key, node_connections[NB_TOTAL-1].iv, ciphertext);
        if (ciphertext_len == -1) {
            t_print("Encryption failed.\n");
            return -1;
        }
        sgx_thread_mutex_lock(&runtime_scheduler->mutex);
        runtime_scheduler->canSend = WAIT;
        runtime_scheduler->isCounting = 1;
        sgx_thread_mutex_unlock(&runtime_scheduler->mutex);

        calibration_start_tsc = runtime_scheduler->timestamps;
        send_udp_packet(node_connections[NB_TOTAL-1], ciphertext, ciphertext_len);
        wait_in_enclave(1);
    }

    sgx_thread_mutex_lock(&runtime_scheduler->mutex);
    runtime_scheduler->canSend = NOT_DELAYED;
    sgx_thread_mutex_unlock(&runtime_scheduler->mutex);

    while(number_of_instant_responses > 0){
        t_print("CLIENT : number_of_instant_responses : %d\n", number_of_instant_responses);
        while(runtime_scheduler->canSend == WAIT){
            continue;
        }

        calibration_end_tsc = runtime_scheduler->timestamps;
        t_print("CLIENT : canSend : %d\n", runtime_scheduler->canSend);
        if(runtime_scheduler->canSend == NOT_DELAYED){
            if(calibration_end_tsc-calibration_start_tsc > 0 && calibration_end_tsc-calibration_start_tsc < 1000000000000000){
                number_of_instant_responses--;
                mean_tsc_0 += calibration_end_tsc - calibration_start_tsc;
                t_print("CLIENT : %d ms end-start :  %lld\n", waiting_time, calibration_end_tsc-calibration_start_tsc);
            }
        }

        snprintf((char*)plaintext, sizeof(plaintext), "c;%d;%d;%d", own_port, NOT_DELAYED, 0);
        ciphertext_len = aes_encrypt(plaintext, strlen((char*)plaintext), node_connections[NB_TOTAL-1].key, node_connections[NB_TOTAL-1].iv, ciphertext);
        if (ciphertext_len == -1) {
            t_print("Encryption failed.\n");
            return -1;
        }          

        sgx_thread_mutex_lock(&runtime_scheduler->mutex);
        runtime_scheduler->isCalibrating = 0;
        sgx_thread_mutex_unlock(&runtime_scheduler->mutex);
        calibration_start_tsc = runtime_scheduler->timestamps;
        t_print("CLIENT : Sending UDP packet\n");
        send_udp_packet(node_connections[NB_TOTAL-1], ciphertext, ciphertext_len);
        wait_in_enclave(1);
    }

    t_print("CLIENT \n\n\n Finsihehd\n\n\n");


    mean_tsc_0 /= (int)n;
    mean_tsc_500 /= (int)n;
    t_print("CLIENT : count : %lld\n", runtime_scheduler->count);
    runtime_scheduler->count /= n;
    t_print("CLIENT : count : %lld\n", runtime_scheduler->count);
    drift_rate = (mean_tsc_500-mean_tsc_0)/(waiting_time*1000);
    add_opp_in_2ms = 2*runtime_scheduler->count/(waiting_time);
    t_print("CLIENT : Calibration result :\ndrifte_rate :%lld\nadd_opp_in_2ms : %lld\n", drift_rate, add_opp_in_2ms);

    return 0;
}

   
int Client::run() {
    /*
    In : void
    Out : int : 0 if success, -1 if failure
    Description : Run the client. The client connects to the nodes and sends messages to them.
    */
    long long ts = 0;
    std::string cryptographic_key;
    std::string port;
    
    int bytes_written;
    int error = 0;
    int ret = 1;
    int ciphertext_len;
    

    X509* certificate = nullptr;
    EVP_PKEY* pkey = nullptr;
    SSL_CONF_CTX* ssl_confctx = SSL_CONF_CTX_new();

    SSL* ssl_session = nullptr;
    int client_sock = -1;
    int index = -1;
    int nb_dest = 0;
    int available_nodes[NB_NODE] = {-1, -1};
    int nb_available_nodes = 0;
    int nb_askable_nodes = 0;

    while(true){
        nb_dest = 0;
        available_nodes[0] = -1;
        available_nodes[1] = -1;
        unsigned char ciphertext[128];
        establish_socket();
        
        for(int i = 0; i < NB_TOTAL; i++){
            if(node_connections[i].socket_fd != -1 && node_connections[i].is_connected == 0){
                t_print("CLIENT : exchanging key with node %d\n", node_connections[i].node_port);
                exchange_key(node_connections[i]);
                t_print("CLIENT : key exchanged with %d\n", node_connections[i].node_port);
            }
        }
        if(runtime_scheduler->isCalibrating == 1 && node_connections[NB_TOTAL-1].socket_fd != -1 && node_connections[NB_TOTAL-1].is_connected == 1){
            t_print("CLIENT : isCalibrating : %d\n", runtime_scheduler->isCalibrating);
            calibrate();
        }
        if(runtime_scheduler->shouldSend == 1){
            index = NB_TOTAL-2;
            unsigned char plaintext[200];
            snprintf((char*)plaintext, sizeof(plaintext), "t;%d;%lld", own_port,runtime_scheduler->timestamps);
            t_print("CLIENT : timestamp to forward : %lld\n", runtime_scheduler->timestamps);
            ciphertext_len = aes_encrypt(plaintext, strlen((char*)plaintext), node_connections[index].key, node_connections[index].iv, ciphertext);
            if (ciphertext_len == -1) {
                t_print("Encryption failed.\n");
                return EXIT_FAILURE;
            }
            if(node_connections[index].socket_fd != -1 && node_connections[index].is_connected == 1){
                t_print("CLIENT : Sending timestamp to %d\n", node_connections[index].node_port);
                send_udp_packet(node_connections[index], ciphertext, ciphertext_len);
            }
            wait_in_enclave(1);  
            sgx_thread_mutex_lock(&runtime_scheduler->mutex);
            runtime_scheduler->shouldSend = 0;
            sgx_thread_mutex_unlock(&runtime_scheduler->mutex);
        }

        if(runtime_scheduler->isAsking == 1){

            for(int i = 0; i < 4; i++){
                if(runtime_scheduler->dest[i] != 0){//si client demande, nb_dest = 1
                    nb_dest++;
                    t_print("%d\n", runtime_scheduler->dest[i]);
                }
            }
            for(int i = 0; i < NB_TOTAL && nb_dest > 0; i++){
                if(nb_dest == 0){
                    break;
                }

                else if(nb_dest > 0 && in_array(runtime_scheduler->dest, node_connections[i].node_port)){ // on regarde si dans le tableau des destinataires du message, le port i est dedans
                    sgx_thread_mutex_lock(&runtime_scheduler->mutex);
                    runtime_scheduler->dest[i] = 0;
                    sgx_thread_mutex_unlock(&runtime_scheduler->mutex);
                    nb_dest--;
                    index = i;
                }

            
                if(node_connections[index].socket_fd != -1 && node_connections[index].is_connected == 1){
                    //if(runtime_scheduler->is_out_of_enclave == 0){
                    if(*out_enclave == 0){
                        sgx_thread_mutex_lock(&runtime_scheduler->mutex);
                        runtime_scheduler->isAsking = 0;
                        runtime_scheduler->index = -1;
                        unsigned char plaintext[200];
                        snprintf((char*)plaintext, sizeof(plaintext), "t;%d;%lld", own_port, runtime_scheduler->timestamps);
                        ciphertext_len = aes_encrypt(plaintext, strlen((char*)plaintext), node_connections[index].key, node_connections[index].iv, ciphertext);
                        if (ciphertext_len == -1) {
                            t_print("Encryption failed.\n");
                            return EXIT_FAILURE;
                        }
                        if(node_connections[index].socket_fd != -1 && node_connections[index].is_connected == 1){
                            send_udp_packet(node_connections[index], ciphertext, ciphertext_len);
                        }
                        wait_in_enclave(1);  
                        sgx_thread_mutex_unlock(&runtime_scheduler->mutex);
                    }
                    
                    else{
                        t_print("CLIENT : Out of enclave\n");
                        unsigned char plaintext[200];
                        nb_available_nodes = 0;
                        for(int i = 0; i < NB_NODE; i++){
                            //look for an available node to ask
                            if(node_connections[i].socket_fd != -1 && node_connections[i].is_connected == 1){
                                available_nodes[i] = node_connections[i].node_port;
                                nb_available_nodes++;
                            }
                            else{
                                available_nodes[i] = -1;
                            }
                        }
                        nb_askable_nodes = compareArray(available_nodes, runtime_scheduler->dest, nb_available_nodes);
                        if(nb_askable_nodes == 0){
                            t_print("CLIENT : need to ask trusted server\n");
                            snprintf((char*)plaintext, sizeof(plaintext), "p;%d;%d;%d", runtime_scheduler->dest[0], runtime_scheduler->dest[1], own_port);
                            index = NB_TOTAL-1;//Trusted server indices 

                        }
                        
                        else if(nb_askable_nodes == 2){
                            //ask first available node
                            t_print("CLIENT : ask first available node\n");
                            snprintf((char*)plaintext, sizeof(plaintext), "p;%d", own_port);
                            index = 0;
                        }
                        else if(nb_askable_nodes == 1){
                            t_print("CLIENT : one node already asked\n");
                            if(available_nodes[0] > 0){
                                snprintf((char*)plaintext, sizeof(plaintext), "p;%d;%d", runtime_scheduler->dest[0], own_port);
                                index = 0;
                            }
                            else{
                                snprintf((char*)plaintext, sizeof(plaintext), "p;%d;%d", runtime_scheduler->dest[1], own_port);
                                index = 1;
                            }
                        }
                        ciphertext_len = aes_encrypt(plaintext, strlen((char*)plaintext), node_connections[index].key, node_connections[index].iv, ciphertext);
                        t_print("CLIENT : Sending timestamp to %d\n", node_connections[index].node_port);
                        send_udp_packet(node_connections[index], ciphertext, ciphertext_len);
                        wait_in_enclave(2);

                        sgx_thread_mutex_lock(&runtime_scheduler->mutex);
                        runtime_scheduler->isAsking = 0;
                        runtime_scheduler->index = -1;
                        sgx_thread_mutex_unlock(&runtime_scheduler->mutex);
                    }
                    
                }
            }
        }   
    }
            
    
    
clean:
    for(int i = 0; i < NB_TOTAL; i++){
        close_ssl_connection(node_connections[i]);  
    }
    SSL_CTX_free(ctx);
    //return ret;
}
