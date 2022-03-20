/**
 * @ameynare_assignment1
 * @author  Amey Naresh Narvekar <ameynare@buffalo.edu>
 * @version 1.0
 *
 * @section LICENSE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details at
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @section DESCRIPTION
 *
 * This contains the main function. Add further description here....
 */
#include <stdio.h>
#include <stdlib.h>

#include "../include/global.h"
#include "../include/logger.h"

#define MAX_LENGTH 1024



/**
 * main function
 *
 * @param  argc Number of arguments
 * @param  argv The argument list
 * @return 0 EXIT_SUCCESS
 */
int main(int argc, char **argv)
{
	/*Init. Logger*/
	cse4589_init_log(argv[2]);

	/*Clear LOGFILE*/
	fclose(fopen(LOGFILE, "w"));
	
	/*Start Here*/
	// This a variable is used as a flag to indicate client or server. 0 -> Server and 1 -> Client
	int isClient = 0;
	int sockfd = 0;

	/*Start Here*/
	if (strcmp(argv[1], "s") == 0)
	{
		sockfd = createSocket_server();
		bind_server();
		listen_server();
		accept_server();
	}

	if (strcmp(argv[1], "c") == 0)
	{
		isclient = 1;
		sockfd = createSocket_client();
		bind_client();
		connect_client();
	}

	shellloop();

	
	// // Defining structures for hosts and messages
	// struct host {
	// 	char *hostname;
	// 	char *ip_addr;
	// 	int port_num;
	// 	int num_msg_sent;
	// 	int num_msg_rcv;
	// 	char *status;
	// 	int fd;
	// 	struct host * blocked;
	// 	struct host * next_host;
	// 	bool is_logged_in;
	// 	bool is_server;
	// 	struct message * queued_messages;
	// };

	// struct message {
	// 	char *text;
	// 	struct host * from_client;
	// 	struct message * next_message;
	// 	bool is_broadcast;
	// };
	




	return 0;
}


void shellloop()
{
	// Basic shell, referenced from https://stackoverflow.com/questions/4788374/writing-a-basic-shell
	char line[BUF_LEN];
	char *command;

	while (1) 
	{
		printf("$ ");

		if (!fgets(line, BUF_LEN, stdin)) 
			break;

		command = strtok(line, "\n");

		// Read inputs and call associated methods
		if (strcmp(command, "AUTHOR") == 0)
		{
			cse4589_print_and_log("[%s:SUCCESS]\n", command);
			author();
			cse4589_print_and_log("[%s:END]\n", command);
		}
		else if (strcmp(command, "IP") == 0)
		{
			cse4589_print_and_log("[%s:SUCCESS]\n", command);
			ip();
			cse4589_print_and_log("[%s:END]\n", command);
		}
		else if (strcmp(command, "EXIT") == 0)
		{
			cse4589_print_and_log("[%s:SUCCESS]\n", command);
			exitprogram();
			cse4589_print_and_log("[%s:END]\n", command);
		}
		else if (strcmp(command, "PORT") == 0)
		{
			cse4589_print_and_log("[%s:SUCCESS]\n", command);
			port();
			cse4589_print_and_log("[%s:END]\n", command);
		}
		else if (strcmp(command, "LIST") == 0)
		{
			cse4589_print_and_log("[%s:SUCCESS]\n", command);
			listclients();
			cse4589_print_and_log("[%s:END]\n", command);
		}
		else
		{
			cse4589_print_and_log("[%s:ERROR]\n", command);
			cse4589_print_and_log("[%s:END]\n", command);
		}

	}

}

void author()
{
	char your_ubit_name[9] = "dakotale";
	cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", your_ubit_name);
}

void ip()
{
	// Adapted from https://www.geeksforgeeks.org/c-program-display-hostname-ip-address/
	char hostbuffer[32];
    char *IP;
    struct hostent *host;
    int hostname;
 
    // To retrieve hostname
    hostname = gethostname(hostbuffer, sizeof(hostbuffer));
 
    // To retrieve host information
    host = gethostbyname(hostbuffer);
 
    // To convert an Internet network
    // address into ASCII string
    // Also referencing https://beej.us/guide/bgnet/html/multi/inet_ntoaman.html
    IP = inet_ntoa(*((struct in_addr*)host->h_addr_list[0]));
 
    cse4589_print_and_log(IP);
    cse4589_print_and_log("\n");
}

void port()
{
	printf("This part requires socket API.\n");
}

void listclients()
{
	printf("This part requires socket API.\n");
}

void exitprogram()
{
	exit(0);
}

//---------------------------------------CLIENT-----------------------------------------------//

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
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0)
		cse4589_print_and_log("Can't open socket");

	cse4589_print_and_log("Create function on server called");
	cse4589_print_and_log("\n");

	return sockfd;
}

void bind_client()
{
	struct sockaddr_in ass;
	int sockfd = 0;
	sockfd = createSocket_client();

	ass.sin_family = AF_INET;
	ass.sin_addr.s_addr = INADDR_ANY;
	ass.sin_port = htons(PORT);

	bind(sockfd, (struct sockaddr *) &ass, sizeof(ass));

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


//---------------------------------------SERVER-----------------------------------------------//
#define PORT 3490

int createSocket_server()
{
	int sockfd = 0;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0)
		cse4589_print_and_log("Can't open socket");

	cse4589_print_and_log("Create function on server called");
	cse4589_print_and_log("\n");

	return sockfd;
}

void bind_server()
{
	struct sockaddr_in ass;
	int sockfd = 0;
	sockfd = createSocket_server();

	ass.sin_family = AF_INET;
	ass.sin_addr.s_addr = INADDR_ANY;
	ass.sin_port = htons(PORT);

	bind(sockfd, (struct sockaddr *) &ass, sizeof(ass));
	cse4589_print_and_log("Bind function on server called");
	cse4589_print_and_log("\n");
}

void listen_server()
{
	int sockfd = 0;
	sockfd = createSocket_server();
	listen(sockfd, SOMAXCONN);
	cse4589_print_and_log("Listen function on server called");
	cse4589_print_and_log("\n");
}

void accept_server()
{
	struct sockaddr_in ass;
	int sockfd = 0;
	int asslen;
	sockfd = createSocket_server();

	ass.sin_family = AF_INET;
	ass.sin_addr.s_addr = INADDR_ANY;
	ass.sin_port = htons(PORT);

	asslen = sizeof(ass);
	accept(sockfd, (struct sockaddr *) &ass, &asslen);

	cse4589_print_and_log("Accept function on server called");
	cse4589_print_and_log("\n");
}