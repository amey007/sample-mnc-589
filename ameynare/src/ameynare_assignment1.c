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
#include <string.h>
// For uppercase (toupper function)
// May not be needed
//#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#include "../include/global.h"
#include "../include/logger.h"
#include "../src/logger.c"

// #define MAX_LENGTH 256
#define MAXDATASIZE 500
#define CMDSIZE 50
#define BACKLOG 5
#define STDIN 0

// functions predeclarations
int is_Valid_Port(const char *input);
int connect_to_host(char *server_ip, int server_port, int c_port);
int bind_socket(int c_port);
void get_IP();
void author();
int is_Valid_IP(char *ip);

//Reused Structure objects
struct client_msg
{
	char cmd[20];
	char ip[32];
	char info[256];
};

struct user {
	char hostname[35]; 
	char ip_addr[16]; 
	int port; 
	int status; // -1=disconnected, 0=logged-out, 1=logged-in,
	int socket; 	
	int msg_sent; 
	int msg_recv; 	
	char buffered[100][MAXDATASIZE]; 
	int buff_size; 	
	int num_blocked; 
	struct user *blocked[4]; // array of IPs that are blocked by the current user	
	struct user *list_storage[4]; // list of LOCAL user storage for EXCEPTIONS (send, BLOCK, UNBLOCK
	int num_users; 
};




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

	// variable for socket file descriptor
	int sockfd = 0;
	int fdsocket = 0;


	/*Start Here*/
	//Initiaties the further steps only when the segment is passed
	if (argc == 3)
	{
		// This segment creates socket for the server and binds it to a port and puts it in listen mode
		if (strcmp(argv[1], "s") == 0)
		{
			// TODO - ALOK
			isClient = 0;
			server(argv[2])
		}

		// This segment creates socket for the client and binds it to a port and puts it in connect mode
		else if (strcmp(argv[1], "c") == 0)
		{
			isclient = 1;
			client(argv[2]);
		}
		else 
		{
			printf("Please enter only two argument \'c\' or \'s\' and \'PORT NUMBER\'");
			exit(-1); //returns exit code -1 to the parent
		}
	}
	else 
	{
		printf("Please enter only two argument \'c\' or \'s\' and \'PORT NUMBER\'");
		exit(-1); //returns exit code -1 to the parent
	}
		
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


void client(char *port_str){
	
	if(!is_Valid_Port(port_str)){
		perror("Invalid Port Number entered!")
	}
	int port = atoi(port_str);  //Converts the port from char to int

	int bind_port=bind_the_socket(client_port); //Socket creation and bind
	int loggedin=0;//using as bool
	if(bind_port==0)
	{
		exit(-1);
	}

	int server = -1; //check
	char *list_storage = (char*) malloc(sizeof(char)*1000); // Local copy of LIST information for client, updates on REFRESH command
	memset(list_storage, '\0', 1000); 
	int refresh = 0, loggedin = 0;      //check
	int sel, sock_idx, client_head_socket;
	struct client_msg data;                        // creating a instance of client msg struct
	fd_set client_watch_list, client_master_list;
	
	// Initializes file descripter to have zero bits
	FD_ZERO(&client_master_list); 
	FD_ZERO(&client_watch_list);

	// Set STDIN to master_list
	FD_SET(STDIN, &client_master_list); 
	
	client_head_socket = STDIN; 

	while(1) { 		
		memcpy(&client_watch_list, &client_master_list, sizeof(client_master_list)); //making copy of client watchlist and masterlist

		// select() ->  indicates which of the specified file descriptors is ready for reading, blocks if none is ready
		if ((sel = select(client_head_socket + 1, &client_watch_list, NULL, NULL, NULL)) < 0) { 
			perror("select() error"); 
			exit(-1);
		} 
		else { 
			// fetching the available socket  
			for (sock_idx = 0; sock_idx <= client_head_socket; ++sock_idx) { 
				if (FD_ISSET(sock_idx, &client_watch_list)) { 
					if (sock_idx == STDIN) //check
					{ // get client input
						char *input = (char*) malloc(sizeof(char)*MAXDATASIZE);
						memset(input, '\0', MAXDATASIZE);

						if(fgets(input, MAXDATASIZE-1, stdin) == NULL) { // Checks if there is a command entered in the standard  input
							exit(-1);
						}
						
						trim(input); // removing the null characters
						
						char *cmd = (char*) malloc(sizeof(char)*CMDSIZE);
						memset(cmd, '\0', CMDSIZE); 
						int num_args = 0; 
						char *args[100];
						if (strcmp("", input) != 0) { 
							char *temp = (char*) malloc(sizeof(char)*strlen(input)); 
							strcpy(temp, input); 
							args[num_args] = strtok(temp, " "); 
							while (args[num_args] != NULL) { 
								args[++num_args] = strtok(NULL, " "); 
							}
							strcpy(cmd, args[0]); 
							trim(cmd);                               //Command entered in the terminal fetched
							if (num_args == 1) { 
								args[0][strlen(args[0])] = '\0';
							}
							free(temp); //check was commented
						}

						// Based on identified command, call respective methods
						if (strcmp(cmd, "AUTHOR") == 0)
						{
							cse4589_print_and_log("[%s:SUCCESS]\n", cmd);
							author();
							cse4589_print_and_log("[%s:END]\n", cmd);
						}
						else if (strcmp(cmd, "IP") == 0)
						{
							//print and log statements are handled in the function get_IP()
							get_IP();							
						}
						else if (strcmp(cmd, "PORT") == 0)
						{
							cse4589_print_and_log("[%s:SUCCESS]\n", cmd);
							cse4589_print_and_log("PORT:%d\n", 	port);     //Already stored in the variable port
							cse4589_print_and_log("[%s:END]\n", cmd);
						}
						
						else if (strcmp(cmd, "LIST") == 0 && loggedin == 0)
						{
							strcpy(data.cmd,"LIST");
							if(send(server, &data, sizeof(data), 0) == sizeof(data))  //server should be zero CHECK
							{
								cse4589_print_and_log("[LIST:SUCCESS]\n");
							}
							else
							{
								cse4589_print_and_log("[LIST:ERROR]\n");
							}
												
						}
						else if (strcmp(cmd, "LOGIN") == 0) {
							if (num_args == 3) { 
								server = connect_to_host(args[1], args[2], port); 
								if (server > -1) { 
									FD_SET(server, &master_list); 
									if (server > head_socket) { 
										head_socket = server; 
									} 
									login = 1; 
								} 
								else { 
									cse4589_print_and_log("[%s:ERROR]\n", cmd);
									cse4589_print_and_log("[%s:END]\n", cmd);
								}
							}
						}


						else if (strcmp(cmd, "EXIT") == 0)
						{
							cse4589_print_and_log("[%s:SUCCESS]\n", cmd);
							exitprogram();
							cse4589_print_and_log("[%s:END]\n", cmd);
						}
						else
						{
							cse4589_print_and_log("[%s:ERROR]\n", cmd);
							cse4589_print_and_log("[%s:END]\n", cmd);
						}

					}
					else{//DO NOTHING}

				}
				
			}
		}
	}
}



//---------------------------------------SERVER CLIENT FUNCTIONS-----------------------------------------//
void author()
{
	char your_ubit_name[9] = "ameynare";
	cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", your_ubit_name);
}

void get_IP()
{	
	// This functions connects to google to fetch the IP
    const char* google_dns = "8.8.8.8";
    int dns_port = 53;
    
    struct sockaddr_in saddr;     
    int sockfd = socket ( AF_INET, SOCK_DGRAM, 0);  //Creating a socket
     
    if(sockfd < 0) { perror("Socket error"); }
     
    memset( &saddr, 0, sizeof(saddr) );
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = inet_addr(google_dns);
    saddr.sin_port = htons( dns_port );
 
    connect( sockfd , (const struct sockaddr*) &saddr, sizeof(saddr) );  //
     
    bzero(&saddr, sizeof(saddr))
    int len = sizeof(saddr);
    getsockname(sockfd, (struct sockaddr*) &saddr, &len);  //retrieves the locally-bound name of the specified socket, store this address in the sockaddr structure
         
    char ip_addr[16];
    const char* p = inet_ntop(AF_INET, &saddr.sin_addr, ip_addr, sizeof(ip_addr));  // convert a numeric address into a dotted format IP address
         
    if(p != NULL)
    {
    	cse4589_print_and_log("[IP:SUCCESS]\n");
        cse4589_print_and_log("IP:%s\n",ip_addr);
    }
    else
    {
    	cse4589_print_and_log("[IP:ERROR]\n");

    }
    close(sockfd);  //closes the socket
}

int bind_socket(int c_port){
	
	struct sockaddr_in my_addrs;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);// return socket file descriptor
    if(sockfd < 0)
    {
       perror("Failed to create socket");
       return 0;
    }

    //setting up client socket
    my_addrs.sin_family=AF_INET;
    my_addrs.sin_addr.s_addr=INADDR_ANY;
    my_addrs.sin_port=htons(c_port);
    int optval=1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    if(bind(sockfd, (struct  sockaddr*) &my_addrs, sizeof(struct sockaddr_in)) == 0)
    {
    	printf("\nclient binded to port correctly\n");
    	return 1;
    }
    else
    {
    	printf("\nError in binding client port\n");
    	return 0;
    }
}

int connect_to_host(char *server_ip, int server_port, int c_port)
{
    int len;
    struct sockaddr_in remote_server_addr;

    bzero(&remote_server_addr, sizeof(remote_server_addr));
    remote_server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, server_ip, &remote_server_addr.sin_addr);//inet_pton - convert IPv4 and IPv6 addresses from text to binary form
    remote_server_addr.sin_port = htons(server_port);//function converts the unsigned short integer hostshort from host byte order to network byte order.

    if(connect(sockfd, (struct sockaddr*)&remote_server_addr, sizeof(remote_server_addr)) < 0)
    {
        perror("Connect failed");
    }
    else{
    	printf("\nLogged in\n");
    }
    return sockfd;
}

int is_Valid_IP(char *ip) { 	
	char temp[16]; 
	memset(temp, '\0', 16);
	strcpy(temp, ip); 
	
	int num_args = 0; 
	char *args[20]; 
	
	args[num_args] = strtok(temp, "."); 
	while (args[num_args] != NULL) { 
		args[++num_args] = strtok(NULL, "."); 
	}
	
	if (num_args != 4) { 
		return 0; 
	}
	else { 
		for (int i = 0; i < num_args; ++i) { 
			for (int j = 0; j < strlen(args[i]); ++j) { 
				if (args[i][j] < '0' || args[i][j] > '9') {					
					return 0;
				}
			}
			int check = atoi(args[i]); 
			if (check > 256 || check < 0) { 			
				return 0;
			}
		}
	}
	return 1;
}

int connect_to_host_og(char *server_ip, char *server_port_char, int host_port) {
	if (!is_Valid_IP(server_ip) || !is_Valid_Port(server_port_char)) { 
		cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
		cse4589_print_and_log("[%s:END]\n", "LOGIN");
		return -1;
	}
	else { 
		int server_port = atoi(server_port_char); 
		int socketfd; 
		struct sockaddr_in server_addr, client_addr;

		socketfd = socket(AF_INET, SOCK_STREAM, 0); 
		if (socketfd < 0) { 
			perror("socket() failed\n"); 
		}
		bzero(&client_addr, sizeof(client_addr)); 
		client_addr.sin_family = AF_INET;
		client_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
		client_addr.sin_port = htons(host_port); 
		if (bind(socketfd, (struct sockaddr *) &client_addr, sizeof(struct sockaddr_in)) != 0) { 
			perror("failed to bind port to client"); 
		}
		
		bzero(&server_addr, sizeof(server_addr));
		server_addr.sin_family = AF_INET;
		inet_pton(AF_INET, server_ip, &server_addr.sin_addr);
		server_addr.sin_port = htons(server_port);

		if(connect(socketfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
			socketfd = -1; 
			cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
			cse4589_print_and_log("[%s:END]\n", "LOGIN");
			return -1; 
		}
		return socketfd;
	}
    
}
//---------------------------------------HELPER FUNCTIONS-----------------------------------------------//

int is_Valid_Port(const char *input) {
	int i = 0;
	if(input[i] == '-') { return 0; }
	for(; input[i] != '\0'; i++) {
		if(!isdigit(input[i])) return 0;
	}
	return 1;
}
