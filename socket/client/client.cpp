#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "report.h"
#include "test_dev_key.h"

int main(int argc, char **argv)
{
  int sockfd;
  struct sockaddr_in address;
  char buffer[2048] = {0};
  char data[2048] = {0};
  char datasend[] = "This is data from client\0";
  Report report;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("socket failed");
    return -1;
  }

  address.sin_family = AF_INET;
  address.sin_port = htons(4097);

  if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) <= 0) {
    printf("\nInvalid address/ Address not supported \n");
    return -1;
  }

  if (connect(sockfd, (struct sockaddr *) &address,
              sizeof(address)) < 0) {
    perror("connect failed");
    return -1;
  }

  read(sockfd, buffer, 2048);
  
  report.fromBytes((uint8_t *) buffer);
  if (report.checkSignaturesOnly(_sanctum_dev_public_key)) {
    std::cout<<"Attestation report SIGNATURE is valid\n";
    std::cout<<report.stringfy()<<std::endl;
  } else {
    std::cout<<"Attestation report is invalid\n"; 
    return 0;
  }
  
  memcpy(data, report.getDataSection(), report.getDataSize());
    
  std::cout<<"Data Recive: "<<(char* )data<<std::endl;
  
  std::cout<<"Data Send: " << datasend <<std::endl;
  
  send(sockfd, datasend, strlen(datasend), 0);

  close(sockfd);

  return 0;
}
