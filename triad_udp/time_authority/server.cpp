// Source: https://stackoverflow.com/questions/53051590/udp-server-client-c-sendto-recvfrom
#include <iostream>
#include <string.h>
#include <fstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sodium.h>
using namespace std;

#define PORT 12340
#define DRIFT_STR "Drift"

int main() {
  int serSockDes, readStatus;
  struct sockaddr_in serAddr, cliAddr;
  socklen_t cliAddrLen;
  char buff[1024] = {0};
  char msg[] = "Hello to you too!!!\n";

  unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
  memset(nonce, 0, sizeof(nonce));

  unsigned char key[crypto_aead_aes256gcm_KEYBYTES];
  const char* test_key = "b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4";
  sodium_hex2bin(key, crypto_aead_aes256gcm_KEYBYTES,
                       test_key, strlen(test_key),
                       NULL, NULL, NULL);

  //creating a new server socket
  if ((serSockDes = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket creation error...\n");
    exit(-1);
  }

  //binding the port to ip and port
  serAddr.sin_family = AF_INET;
  serAddr.sin_port = htons(PORT);
  serAddr.sin_addr.s_addr = INADDR_ANY;

  if ((bind(serSockDes, (struct sockaddr*)&serAddr, sizeof(serAddr))) < 0) {
    perror("binding error...\n");
    close(serSockDes);
    exit(-1);
  }

  while (true){  
    cliAddrLen = sizeof(cliAddr);
    readStatus = recvfrom(serSockDes, buff, 1024, 0, (struct sockaddr*)&cliAddr, &cliAddrLen);
    if (readStatus < 0) { 
      perror("reading error...\n");
      close(serSockDes);
      exit(-1);
    }

    unsigned char buff_dec[sizeof(buff)];
    unsigned long long buff_len_dec = sizeof(buff);
    if (crypto_aead_aes256gcm_decrypt(buff_dec, &buff_len_dec,
                                      NULL, (const unsigned char*)buff, readStatus,
                                      NULL, 0, nonce, key) != 0) {
        perror("Decryption failed\r\n");
        return -1;
    }

    const long long int recvd_calib_msg_count = *(const long long int*)((const char*)buff_dec+strlen(DRIFT_STR));
    const int sleep_time = *(const int*)((const char*)buff_dec+strlen(DRIFT_STR)+sizeof(recvd_calib_msg_count));

    cout.write((const char*)buff_dec, buff_len_dec);
    cout << endl;
    cout << "Received from "<< cliAddr.sin_port<<" calib_msg: " << recvd_calib_msg_count << " and will sleep for "<< sleep_time << "ms" << endl;

    usleep(sleep_time*1000);

    unsigned char buff_enc[buff_len_dec + crypto_aead_aes256gcm_ABYTES];
    unsigned long long buff_len_enc = buff_len_dec + crypto_aead_aes256gcm_ABYTES;

    crypto_aead_aes256gcm_encrypt(buff_enc, &buff_len_enc,
                                    buff_dec, buff_len_dec,
                                    NULL, 0, NULL, nonce, key);

    if (sendto(serSockDes, buff_enc, buff_len_enc, 0, (struct sockaddr*)&cliAddr, cliAddrLen) < 0) { 
      perror("sending error...\n");
      close(serSockDes);
      exit(-1);
    }
  }

  close(serSockDes);
  return 0;
}