#include "common.h"

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
        t_print("Error: Cannot create socket %d.\n", errno);
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
            "failed to connect to %s:%s (errno=%d)\n",
            server_name,
            server_port,
            errno);
        close(sockfd);
        if (res != 0)
            t_print("OCALL: error closing socket\n");
        sockfd = -1;
        goto done;
    }
    //t_print(TLS_CLIENT "connected to %s:%s\n", server_name, server_port);

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
        t_print("socket creation failed\n");
        goto exit;
    }

    if (setsockopt(
            server_socket,
            SOL_SOCKET,
            SO_REUSEADDR,
            (const void*)&reuse,
            sizeof(reuse)) < 0)
    {
        t_print("setsocket failed \n");
        goto exit;
    }

    if (bind(server_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        t_print("port : %d\n", port);
        t_print("server_socket : %d\n", server_socket);
        t_print("Unable to bind socket to the port\n");
        goto exit;
    }

    if (listen(server_socket, 20) < 0)
    {
        t_print("Unable to open socket for listening\n");
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
        //std::cerr << "Error creating context." << std::endl;
        //exit(EXIT_FAILURE);
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        t_print("Error initializing encryption.\n");
        //std::cerr << "Error initializing encryption." << std::endl;
        //exit(EXIT_FAILURE);
    }

    int len;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        t_print("Error during encryption.\n");
        //std::cerr << "Error during encryption." << std::endl;
        //exit(EXIT_FAILURE);
    }
    int ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        t_print("Error during final encryption step.\n");
        //std::cerr << "Error during final encryption step." << std::endl;
        //exit(EXIT_FAILURE);
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}


int aes_decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        t_print("Error creating context.\n");
        //std::cerr << "Error creating context." << std::endl;
        return -1;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        t_print("Error initializing decryption.\n");
        //std::cerr << "Error initializing decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        t_print("Error during decryption.\n");
        //std::cerr << "Error during decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int plaintext_len = len;

    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if (ret != 1) {
        t_print("Error during final decryption step.\n");
        //std::cerr << "Error during final decryption step." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

void bin_to_hex(const unsigned char* bin, int bin_len, char* hex) {
    for (int i = 0; i < bin_len; ++i) {
        snprintf(hex + (i * 2), 3, "%02x", bin[i]);
    }
    hex[bin_len * 2] = '\0'; // Null-terminate the string
}

void send_key_iv(SSL* ssl, const unsigned char* key, int key_len, const unsigned char* iv, int iv_len) {
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
        //std::cerr << "Error writing to SSL connection." << std::endl;
        return;
    }
}

int hex_char_to_int(char c) {
    if (std::isdigit(c)) {
        return c - '0';
    } else if (std::isxdigit(c)) {
        return std::tolower(c) - 'a' + 10;
    } else {
        // Handle invalid hex characters if necessary
        return -1;
    }
}

// Function to convert a hex string to a binary array
void hex_to_bin(const char* hex, unsigned char* bin, int bin_len) {
    for (int i = 0; i < bin_len; ++i) {
        int high = hex_char_to_int(hex[2 * i]);
        int low = hex_char_to_int(hex[2 * i + 1]);
        if (high == -1 || low == -1) {
            // Handle error (e.g., invalid hex character)
            return;
        }
        bin[i] = (high << 4) | low;
    }
}

// Function to receive and parse the message
bool receive_key_iv(char* msg, unsigned char* key, int key_len, unsigned char* iv, int iv_len) {
    // Parse the message
    char* token = strtok(msg, ";");
    if (token == nullptr || strcmp(token, "k") != 0) {
        t_print("Invalid message format.\n");
        //std::cerr << "Invalid message format." << std::endl;
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
    
    int shutdown_status = SSL_shutdown(client.ssl_session);
    /*
    if (shutdown_status == 0) {
        shutdown_status = SSL_shutdown(client.ssl_session);
    }
    */
    SSL_free(client.ssl_session);
    //close(client.socket_fd);
    //client.socket_fd = -1;
    client.ssl_session = nullptr;
    EVP_cleanup();

}

void send_udp_packet(node_connection& nc, const char* server_ip, int server_port, int& sockfd, const unsigned char* message, int message_len) {
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        t_print("Invalid address or address not supported.\n");
        //std::cerr << "Invalid address or address not supported." << std::endl;
        return;
    }
    

    int retries = 3;
    int bytes_sent = 0;
    while (retries > 0) {
        t_print("Sending UDP packet\n");
        //bytes_sent = sendto(sockfd, message, message_len, MSG_NOSIGNAL, (struct sockaddr *)&server_addr, sizeof(server_addr));
        bytes_sent = send(sockfd, message, message_len, MSG_NOSIGNAL);
        if (bytes_sent == -1) {
            nc.socket_fd = -1;
            nc.is_connected = 0;
            return;
            t_print("Error sending UDP packet: %s\n", strerror(errno));
            //std::cerr << "Error sending UDP packet: " << strerror(errno) << std::endl;
            if (errno == EINTR) {
                // Interrupted by a signal, retry sending
                retries--;
                continue;
            } else {
                return;
            }
        } else if (bytes_sent != message_len) {
            t_print("Partial send, sent %d of %d bytes.\n", bytes_sent, message_len);
            //std::cerr << "Partial send, sent " << bytes_sent << " of " << message_len << " bytes." << std::endl;
            retries--;
        } else {
            // Successfully sent the message
            break;
        }
    }

    if (bytes_sent == message_len) {
        t_print("Successfully sent UDP packet.\n");
        //std::cout << "Successfully sent UDP packet." << std::endl;
    } else {
        t_print("Failed to send UDP packet after retries.\n");
        //std::cerr << "Failed to send UDP packet after retries." << std::endl;
    }
}

void set_up_udp_socket(const char* server_ip, int server_port, int& sockfd){
    int ret;
    t_print("Setting up UDP socket\n");
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        t_print("Error creating socket.\n");
        //std::cerr << "Error creating socket." << std::endl;
        return;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr2(server_ip);
    server_addr.sin_port = htons(server_port);

    if (bind(sockfd, (const struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        t_print("Error binding socket.\n");
        //std::cerr << "Error binding socket." << std::endl;
        close(sockfd);
        return;
    }
    t_print("Socket bound to %s:%d\n", server_ip, server_port);
}

void receive_udp_packet(node_connection& nc, int& sockfd, unsigned char* key, unsigned char* iv) {
    struct sockaddr_in client_addr;
    unsigned char buffer[BUFSIZE];
    unsigned char decryptedtext[BUFSIZE];
    ssize_t received_bytes;
    int ret;
    //socklen_t client_addr_len = sizeof(client_addr);
    // After select indicates sockfd is ready to read...
    //received_bytes = recvfrom(nc.socket_fd, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&client_addr, &client_addr_len);
    received_bytes = recv(sockfd, buffer, sizeof(buffer), MSG_DONTWAIT);

    if (received_bytes < 0) {
        // Check if the operation would block or if there's another error
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No data available to read, operation would block
            t_print("No data available to read, operation would block.\n");
            //std::cerr << "No data available to read, operation would block." << std::endl;
        } else {
            // An actual error occurred
            t_print("Error on recv\n");
        }
    } else if (received_bytes == 0) {
        // Connection has been gracefully closed
        t_print("Connection closed by the peer.\n");
        //std::cout << "Connection closed by the peer." << std::endl;
        sockfd = -1;
        nc.is_connected = 0;
        return;
    } else {
        // Data was received, process it
    int decryptedtext_len = aes_decrypt(buffer, received_bytes, key, iv, decryptedtext);
    if (decryptedtext_len == -1) {
        t_print("Decryption failed.\n");
        //std::cerr << "Decryption failed." << std::endl;
        close(sockfd);
        return;
    }
    decryptedtext[decryptedtext_len] = '\0'; // Null-terminate the decrypted text
    t_print("Decrypted text is: %s\n", decryptedtext);
    //std::cout << "Decrypted text is: " << decryptedtext << std::endl;
    }

    //close(sockfd);
}

void receive_udp_packet_temp(node_connection& nc, int& sockfd) {
    struct sockaddr_in client_addr;
    unsigned char buffer[BUFSIZE];
    ssize_t received_bytes;
    int ret;

    // After select indicates sockfd is ready to read...
    received_bytes = recv(sockfd, buffer, sizeof(buffer), MSG_DONTWAIT);
    t_print("Received bytes : %ld\n", received_bytes);
    if (received_bytes < 0) {
        // Check if the operation would block or if there's another error
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No data available to read, operation would block
            t_print("No data available to read, operation would block.\n");
            //std::cerr << "No data available to read, operation would block." << std::endl;
        } else {
            // An actual error occurred
            t_print("Error on recv\n");
        }
    } else if (received_bytes == 0) {
        // Connection has been gracefully closed
        t_print("Connection closed by the peer.\n");
        //std::cout << "Connection closed by the peer." << std::endl;
        sockfd = -1;
        nc.is_connected = 0;
        return;
    } else {
    t_print("Decrypted text is: %s\n", buffer);
    //std::cout << "Decrypted text is: " << decryptedtext << std::endl;
    }

    //close(sockfd);
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
