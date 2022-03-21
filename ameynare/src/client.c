
/*This file contains the functions definations for client's socket creation, bind , and connect*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include "../include/global.h"
#include "../include/logger.h"

#define PORT 3490 // the port client will be connecting to 

#define MAXDATASIZE 100 // max number of bytes we can get at once 

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	return &(((struct sockaddr_in*)sa)->sin_addr);
}

int createSocket_client()
{
	int sockfd = 0;
    sockfd = socket(AF_INET, SOCK_STREAM, 0); // return socket file descriptor
    if(sockfd < 0)
    {
       perror("Failed to create socket");
       return 0;
    }
	
	return sockfd;
}

void bind_client()
{
	struct sockaddr_in addr;
	int sockfd = 0;
	sockfd = createSocket_client();

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(PORT);

	bind(sockfd, (struct sockaddr *) &addr, sizeof(addr));

	cse4589_print_and_log("Bind function on client called");
	cse4589_print_and_log("\n");
}

void connect_client()
{
	struct sockaddr_in ass;
	int sockfd = 0;
	sockfd = createSocket_client();

	ass.sin_family = AF_INET;
	ass.sin_addr.s_addr = INADDR_ANY;
	ass.sin_port = htons(PORT);

	connect(sockfd, (struct sockaddr *) &ass, sizeof(ass));

	cse4589_print_and_log("Connect function on client called");
	cse4589_print_and_log("\n");
}