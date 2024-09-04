// Source: https://stackoverflow.com/questions/53051590/udp-server-client-c-sendto-recvfrom
#include <iostream>
#include <string.h>
#include <fstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
using namespace std;

#define PORT 8080

int main() {
  int serSockDes, readStatus;
  struct sockaddr_in serAddr, cliAddr;
  socklen_t cliAddrLen;
  char buff[1024] = {0};
  char msg[] = "Hello to you too!!!\n";

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

  cliAddrLen = sizeof(cliAddr);
  readStatus = recvfrom(serSockDes, buff, 1024, 0, (struct sockaddr*)&cliAddr, &cliAddrLen);
  if (readStatus < 0) { 
    perror("reading error...\n");
    close(serSockDes);
    exit(-1);
  }

  cout.write(buff, readStatus);
  cout << endl;

  if (sendto(serSockDes, msg, strlen(msg), 0, (struct sockaddr*)&cliAddr, cliAddrLen) < 0) { 
    perror("sending error...\n");
    close(serSockDes);
    exit(-1);
  }

  close(serSockDes);
  return 0;
}