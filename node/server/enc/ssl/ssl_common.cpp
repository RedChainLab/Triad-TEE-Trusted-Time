#include "ssl_common.h"

unsigned long inet_addr2(const char *str)
{
    unsigned long lHost = 0;
    char *pLong = (char *)&lHost;
    char *p = (char *)str;
    while (p)
    {
        *pLong++ = atoi(p);
        p = strchr(p, '.');
        if (p)
            ++p;
    }
    return lHost;
}


int create_socket(const char* server_name,const char* server_port)
{
    int sockfd = -1;
    struct sockaddr_in dest_sock;
    int res = -1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        t_print(TLS_CLIENT "Error: Cannot create socket %d.\n", errno);
        goto done;
    }


    dest_sock.sin_family = AF_INET;
    dest_sock.sin_port = htons(atoi(server_port));
    dest_sock.sin_addr.s_addr = inet_addr2(server_name);
    bzero(&(dest_sock.sin_zero), sizeof(dest_sock.sin_zero));
    
    if (connect(
                sockfd, (sockaddr*) &dest_sock,
                sizeof(struct sockaddr)) == -1)
    {
        t_print(
            TLS_CLIENT "failed to connect to %s:%s (errno=%d)\n",
            server_name,
            server_port,
            errno);
        ocall_close(&res, sockfd);
        if (res != 0)
            t_print(TLS_CLIENT "OCALL: error closing socket\n");
        sockfd = -1;
        goto done;
    }

done:
    return sockfd;
}

int create_listener_socket(int port, int& server_socket)
{
    int ret = -1;
    const int reuse = 1;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        t_print(TLS_SERVER "socket creation failed\n");
        goto exit;
    }

    if (setsockopt(
            server_socket,
            SOL_SOCKET,
            SO_REUSEADDR,
            (const void*)&reuse,
            sizeof(reuse)) < 0)
    {
        t_print(TLS_SERVER "setsocket failed \n");
        goto exit;
    }

    if (bind(server_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        t_print(TLS_SERVER "port : %d\n", port);
        t_print(TLS_SERVER "server_socket : %d\n", server_socket);
        t_print(TLS_SERVER "Unable to bind socket to the port\n");
        goto exit;
    }

    if (listen(server_socket, 20) < 0)
    {
        t_print(TLS_SERVER "Unable to open socket for listening\n");
        goto exit;
    }
    ret = 0;
exit:
    return ret;
}


int aes_encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv, unsigned char* ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        t_print("Error creating context.\n");
        return ERROR_RETURN;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        t_print("Error initializing encryption.\n");
        return ERROR_RETURN;
    }

    int len;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        t_print("Error during encryption.\n");
        return ERROR_RETURN;
    }
    int ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        t_print("Error during final encryption step.\n");
        return ERROR_RETURN;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}


int aes_decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        t_print("Error creating context.\n");
        return ERROR_RETURN;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        t_print("Error initializing decryption.\n");
        EVP_CIPHER_CTX_free(ctx);
        return ERROR_RETURN;
    }

    int len;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        t_print("Error during decryption.\n");
        EVP_CIPHER_CTX_free(ctx);
        return ERROR_RETURN;
    }
    int plaintext_len = len;

    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if (ret != 1) {
        t_print("Error during final decryption step.\n");
        EVP_CIPHER_CTX_free(ctx);
        return ERROR_RETURN;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int bin_to_hex(const unsigned char* bin, int bin_len, char* hex) {
    for (int i = 0; i < bin_len; ++i) {
        snprintf(hex + (i * 2), 3, "%02x", bin[i]);
    }
    hex[bin_len * 2] = '\0'; // Null-terminate the string
    return SUCCESS_RETURN;
}

int send_key_iv(SSL* ssl, const unsigned char* key, int key_len, const unsigned char* iv, int iv_len) {
    // Buffer to hold the hex representations and the final message
    const int HEX_KEY_SIZE = key_len * 2 + 1; // 2 chars per byte + null terminator
    const int HEX_IV_SIZE = iv_len * 2 + 1;  // 2 chars per byte + null terminator
    char hex_key[HEX_KEY_SIZE];
    char hex_iv[HEX_IV_SIZE];

    // Convert key and IV to hex
    bin_to_hex(key, key_len, hex_key);
    bin_to_hex(iv, iv_len, hex_iv);

    // Buffer to hold the final message
    char msg[MSG_SIZE];

    // Format the message
    snprintf(msg, MSG_SIZE, "k;%s;%s;", hex_key, hex_iv);
    t_print("msg: %s\n", msg);
    // Send the message over TLS
    int bytes_written = SSL_write(ssl, msg, strlen(msg));
    if (bytes_written <= 0) {
        t_print("Error writing to SSL connection.\n");
        return ERROR_RETURN;
    }
    return SUCCESS_RETURN;
}


int hex_char_to_int(char c) {
    if (std::isdigit(c)) {
        return c - '0';
    } else if (std::isxdigit(c)) {
        return std::tolower(c) - 'a' + 10;
    } else {
        // Handle invalid hex characters if necessary
        return ERROR_RETURN;
    }
}

// Function to convert a hex string to a binary array
int hex_to_bin(const char* hex, unsigned char* bin, int bin_len) {
    for (int i = 0; i < bin_len; ++i) {
        int high = hex_char_to_int(hex[2 * i]);
        int low = hex_char_to_int(hex[2 * i + 1]);
        if (high == -1 || low == -1) {
            // Handle error (e.g., invalid hex character)
            return ERROR_RETURN;
        }
        bin[i] = (high << 4) | low;
    }
    return SUCCESS_RETURN;
}

// Function to receive and parse the message
bool receive_key_iv(char* msg, unsigned char* key, int key_len, unsigned char* iv, int iv_len) {
    // Parse the message
    char* token = strtok(msg, ";");
    if (token == nullptr || strcmp(token, "k") != 0) {
        t_print("Invalid message format.\n");
        return false;
    }

    // Get key
    token = strtok(nullptr, ";");
    if (token == nullptr || strlen(token) != key_len * 2) {
        t_print("Invalid key length in message.\n");
        //std::cerr << "Invalid key length in message." << std::endl;
        return false;
    }
    hex_to_bin(token, key, key_len);

    // Get IV
    token = strtok(nullptr, ";");
    if (token == nullptr || strlen(token) != iv_len * 2) {
        t_print("Invalid IV length in message.\n");
        //std::cerr << "Invalid IV length in message." << std::endl;
        return false;
    }
    hex_to_bin(token, iv, iv_len);

    return true;
}


void close_ssl_connection(node_connection &client) {
    /*
    Close the SSL connection and free the SSL context
    Keep the socket open 
    */
    int shutdown_status = SSL_shutdown(client.ssl_session);
    SSL_free(client.ssl_session);
    client.ssl_session = nullptr;
    EVP_cleanup();

}

void send_udp_packet(node_connection& nc, const unsigned char* message, int message_len) {
    /*
    In: node_connection& nc, const unsigned char* message, int message_len
    Out: void
    Description: Send message via UDP to the node specified in the node_connection struct
    */
    const char* server_ip = nc.node_name;
    int server_port = nc.node_port;
    int sockfd = nc.socket_fd;
    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);

    server_addr.sin_addr.s_addr = inet_addr2(server_ip);
    int retries = 3;
    int bytes_sent = 0;
    while (retries > 0) {
        bytes_sent = sendto(sockfd, message, message_len, MSG_NOSIGNAL, (struct sockaddr *)&server_addr, sizeof(server_addr));
        if (bytes_sent == -1) {
            nc.socket_fd = -1;
            nc.is_connected = 0;
            return;
            t_print("Error sending UDP packet: %s\n", strerror(errno));
            if (errno == EINTR) {
                retries--;
                continue;
            } else {
                return;
            }
        } else if (bytes_sent != message_len) {
            t_print("Partial send, sent %d of %d bytes.\n", bytes_sent, message_len);
            retries--;
        } else {
            break;
        }
    }

    if (bytes_sent == message_len) {
        t_print("Successfully sent UDP packet.\n");
    } else {
        t_print("Failed to send UDP packet after retries.\n");
    }
}

int receive_udp_packet(node_connection& nc, long long* ts, int* already_sent, long long* epoch) {
    /*
    In: node_connection& nc, long long& ts, int* already_sent, long long* epoch
    Out: int
    Description: Receive message via UDP from the node specified in the node_connection struct
    */
    struct sockaddr_in client_addr;
    unsigned char buffer[BUFSIZE];
    unsigned char decryptedtext[BUFSIZE];
    unsigned char new_message[BUFSIZE];
    ssize_t received_bytes;
    int ret;
    long long temp_ts = 0;

    unsigned char* key = nc.key;
    unsigned char* iv = nc.iv;

    int fields[10];
    int nb_fields = 0;

    //received_bytes = recv(nc.socket_fd, buffer, sizeof(buffer), MSG_DONTWAIT);
    received_bytes = recvfrom(nc.socket_fd, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&client_addr, &client_addr_len);
    if (received_bytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            t_print("No data available to read, operation would block.\n");
        } else {
            t_print("COMMON : Error on recv\n");
            nc.is_connected = 0;
            ocall_close(&ret, nc.socket_fd);
            nc.socket_fd = -1;
            return ERROR_RETURN;
        }
    } else if (received_bytes == 0) {
        // Connection has been gracefully closed
        t_print("Connection closed by the peer.\n");
        nc.socket_fd = -1;
        nc.is_connected = 0;
        return ERROR_RETURN;
    } else {
        int decryptedtext_len = aes_decrypt(buffer, received_bytes, key, iv, decryptedtext);
        if (decryptedtext_len == -1) {
            t_print("Decryption failed.\n");
            ocall_close(&ret, nc.socket_fd);
            nc.socket_fd = -1;
            nc.is_connected = 0;
            return ERROR_RETURN;
        }
        decryptedtext[decryptedtext_len] = '\0'; // Null-terminate the decrypted text
        t_print("COMMON : Decrypted text is: %s\n", decryptedtext);

        ret = parseMessage((const char*) decryptedtext, &temp_ts, fields, &nb_fields);
        if(ret == ERROR_RETURN){
            t_print("COMMON : Error parsing message\n");
            return ERROR_RETURN;
        }
        else if(ret == TIMESTAMP){
            if(temp_ts > *ts){
                *epoch = temp_ts;
            }  
            return TIMESTAMP;
        }
        else if(ret == CALIBRATION){
            *epoch = temp_ts;
            if(fields[0] == NOT_DELAYED){//no delay
                return NOT_DELAYED;
            }
            else if(fields[0] == DELAYED){//delayed
                return DELAYED;
            }
            else if(fields[0] == CALIBRATION_COLD_START){
                return CALIBRATION_COLD_START;
            }
            else if(fields[0] == TIMESTAMP){
                return TIMESTAMP;
            }
        }

        else if(ret == PORT){
            for(int i = 0; i < nb_fields; i++){
                already_sent[i] = fields[i];
            }
        }
        else if (ret > 0){
            return ret;

        }

    }
    return 0;
}

int exchange_key(node_connection& nc) {
    generate_symmetric_key(nc.key, KEY_SIZE);
    generate_symmetric_key(nc.iv, IV_SIZE);
    
    send_key_iv(nc.ssl_session, nc.key, KEY_SIZE, nc.iv, IV_SIZE);
    nc.is_connected = 1;
    return 0;
}


void generate_symmetric_key(unsigned char* key, int size) {
    if (!RAND_bytes(key, size)) {
        t_print("Error generating random bytes.\n");
        //std::cerr << "Error generating random bytes." << std::endl;
        //exit(EXIT_FAILURE);
    }

    // For debugging: Print the key in hex format
    t_print("Generated Key: ");
    //std::cout << "Generated Key: ";
    for (int i = 0; i < size; ++i) {
        t_print("%02x", key[i]);
    }
    t_print("\n");
    //std::cout << std::endl;
}

int in_array(int arr[], int val){
    for(int i = 0; arr[i] != 0; i++){
        if(arr[i] == val){
            return 1;
        }
    }
    return 0;
}

int parseMessage(const char* message, long long int* temp_ts, int* fields, int* nb_fields) {
    // Count the numbers (by counting semicolons and adding one)
    int count = 1;
    if( message[0] == 'p' ){//format "p;<own_port>;<port1>;<port2>;...;<portn>"
        for (const char* p = message+2; *p; ++p) {
            if (*p == ';') ++count;
        }

        // Allocate the array
        // Temporary string for strtok
        char* tempStr = strndup(message+2, strlen(message)-2);
        char* token = strtok(tempStr, ";");
        int index = 0;

        while (token != nullptr) {
            (fields)[index++] = atoi(token); // Convert and store
            token = strtok(nullptr, ";"); // Next token
        }

        free(tempStr); // Free the duplicated string
        *nb_fields = count;
        return PORT; // Return the count of numbers
    }
    else if (message[0] == 't'){//format "t;<own_port>;<timestamp>"
        char* tempStr = strndup(message+2, strlen(message)-2);
        char* token = strtok(tempStr, ";");
        fields[0] = atoi(token);
        token = strtok(nullptr, ";");
        *temp_ts = atoll(token);

        free(tempStr); 
        *nb_fields = 2;
        return TIMESTAMP;
    }
    else if (message[0] == 'c'){//format sent : "c;<own_port>;<type>;<waiting_time>", receive : "c;<type>;<timestamps>"
        t_print("COMMON : Calibration message\n");
        for (const char* p = message+2; *p; ++p) {
            if (*p == ';') ++count;
        }
        char* tempStr = strndup(message+2, strlen(message)-2);
        char* token = strtok(tempStr, ";");
        fields[0] = atoi(token);
        token = strtok(tempStr, ";");
        fields[1] = atoll(token);

        free(tempStr); // Free the duplicated string
        *nb_fields = 2;
        return CALIBRATION; // Return the count of numbers
    }
    else{
        return ERROR_RETURN;
    }
}

int compareArray(int* arr1, int* arr2, int nb_avaiable_nodes){
    int nb = 0;
    for(int i = 0; i < 2; i++){
        for(int j = 0; j < 2; j++){
            if(arr1[i] == arr2[j]){
                arr1[i] = 0;
                nb++;
            }
        }
    }
    return nb_avaiable_nodes-nb;
}
