// Source: https://stackoverflow.com/questions/53051590/udp-server-client-c-sendto-recvfrom
#include <iostream>
#include <fstream>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
using namespace std;

#define PORT 8080

int main(int argc, char** argv) {
  int cliSockDes, readStatus;
  struct sockaddr_in serAddr;
  socklen_t serAddrLen;
  char msg[] = "Hello!!!\n";
  char buff[1024] = {0};

  //create a socket
  if ((cliSockDes = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket creation error...\n");
    exit(-1);
  }

  //server socket address
  serAddr.sin_family = AF_INET;
  serAddr.sin_port = htons(PORT);
  serAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if (sendto(cliSockDes, msg, strlen(msg), 0, (struct sockaddr*)&serAddr, sizeof(serAddr)) < 0) {
    perror("sending error...\n");
    close(cliSockDes);
    exit(-1);
  }

  serAddrLen = sizeof(serAddr);
  readStatus = recvfrom(cliSockDes, buff, 1024, 0, (struct sockaddr*)&serAddr, &serAddrLen);
  if (readStatus < 0) {
    perror("reading error...\n");
    close(cliSockDes);
    exit(-1);
  }

  cout.write(buff, readStatus);
  cout << endl;

  close(cliSockDes);
  return 0;
}