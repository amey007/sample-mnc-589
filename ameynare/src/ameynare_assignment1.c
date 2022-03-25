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
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <ctype.h>

#include "../include/global.h"
#include "../include/logger.h"

#define HOSTNAMESTRLEN 60
#define PORTSTRLEN 10
#define CMD_LEN 128
#define BUFLEN 1024
#define MSGLEN 256
#define BACKLOG 4
#define STD_IN 0
#define login 1
#define logout 0

// DECLARING GLOBAL VARIABLES
int socketfd;
int clientsockfd;
int isServer = 0; // denote server - 1, or client - 0
int hostIndex = 0;
int logedin = 0; // a flag to indicate log in, avoid multible log in
char lis_port[PORTSTRLEN];

// CREATING STRUCT DATASTRUCTURE TO MAINTAIN HOST DETAILS
struct host {
	char hostname[HOSTNAMESTRLEN];
	char ip_addr[INET_ADDRSTRLEN]; 
	int portNum;
	int msg_received;
	int msg_sent;
	int status;
	int blockindex;
	struct host *blockedIPs[3];
	int hostsockfd; 
};

struct host hosts[4];
char bufferedmsg[BUFLEN] = "";

fd_set master_list, watch_list;
int maxfd;

//PROTOTYPE DELCLARATIONS OF THE FUNCTIONS USED
void get_IP();
int is_valid_port(const char *input);
int is_valid_IP(const char *ip);
int setup(const char *port);
int strToInt(const char* s);
void packClientInfo(char *list);
void unpack_store(char *list);
int isBlocked(int sender, char *receiver);
void shellCmds(char **cmd, int count);
void server_response(char **arguments, int count, int calling_client);
void initiate(void);

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

	/* initiate Here*/
	if (argc == 3)
	{
		if (strcmp(argv[1], "s") == 0)
		{
			
			isServer = 1;
			strcpy(lis_port, argv[2]);
			setup(argv[2]);
			initiate();
		}

	
		else if (strcmp(argv[1], "c") == 0)
		{
			isServer = 0;
			strcpy(lis_port, argv[2]);
			setup(argv[2]);
			initiate();
		}
		else 
		{
			printf("Please enter only two argument \'c\' or \'s\' and \'PORT NUMBER\'");
			exit(-1); 
		}
	}
	else 
	{
		printf("Please enter only two argument \'c\' or \'s\' and \'PORT NUMBER\'");
		exit(-1); 
	}
		
	return 0;
}

/*--HELPER FUNCTIONS--*/

void get_IP()
{	
	struct sockaddr_in saddr;     
    int sockfd = socket ( AF_INET, SOCK_DGRAM, 0);  //Creating a socket
	
	// This functions connects to google to fetch the IP
    const char* google_dns = "8.8.8.8";
    int dns_port = 53;
     
    if(sockfd < 0)  
		perror("Socket error"); 
     
    memset( &saddr, 0, sizeof(saddr) );
    saddr.sin_addr.s_addr = inet_addr(google_dns);
	saddr.sin_port = htons( dns_port );
	saddr.sin_family = AF_INET;
 
    connect( sockfd , (const struct sockaddr*) &saddr, sizeof(saddr) ); 
     
    bzero(&saddr, sizeof(saddr));
    socklen_t len = sizeof(saddr);
    getsockname(sockfd, (struct sockaddr*) &saddr, &len);  //retrieves the locally-bound name of the specified socket, store this address in the sockaddr structure
         
    char ip_addr[16];
    const char* p = inet_ntop(AF_INET, &saddr.sin_addr, ip_addr, sizeof(ip_addr));  // convert a numeric address into a dotted format IP address
         
    if(p != NULL)
    {
    	cse4589_print_and_log("[IP:SUCCESS]\n");
        cse4589_print_and_log("IP:%s\n",ip_addr);
		cse4589_print_and_log("[IP:END]\n");
    }
    else
    {
    	cse4589_print_and_log("[IP:ERROR]\n");
		cse4589_print_and_log("[IP:END]\n");
    }
    close(sockfd);  //closes the socket
}

int is_valid_port(const char *input) // Checks the entered port is valid or not
{
	int i = 0;
	if(input[i] == '-') 
		return 0;

	while( input[i] != '\0') 
	{
		if(!isdigit(input[i])) 
			return 0;
		i++;
	}
	return 1;
}

int is_valid_IP(const char *ip)  // Checks the entered IP is valid or not
{ 	
	char temp[16]; 
	memset(temp, '\0', 16);
	strcpy(temp, ip); 
	
	int num_args = 0; 
	char *args[20]; 
	
	args[num_args] = strtok(temp, "."); 
	while (args[num_args] != NULL) 
	{ 
		args[++num_args] = strtok(NULL, "."); 
	}
	
	if (num_args != 4) 
	{ 
		return 0; 
	}
	
	else 
	{ 
		for (int i = 0; i < num_args; ++i)
		{ 
			for (int j = 0; j < strlen(args[i]); ++j) 
			{ 
				if ( args[i][j] > '9' || args[i][j] < '0' )
				{					
					return 0;
				}
			}
			int check = atoi(args[i]); 
			if ( check < 0 || check > 256 ) 
			{ 			
				return 0;
			}
		}
	}
	return 1;
}

int setup(const char *port)
{
	struct addrinfo hints, *servinfo, *p;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if(getaddrinfo(NULL, port, &hints, &servinfo) == -1)
	{
		return -1;
	}

	p = servinfo;
	while( p != NULL )
	{
		if((socketfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)  // creates a socket
		{
			continue;
		}

		if(bind(socketfd, p->ai_addr, p->ai_addrlen) == -1)  //binds the socket 
		{
			close(socketfd);
			continue;
		}
		break;
		p = p -> ai_next;
	}

	if(p == NULL) 
		return -1;
	
	freeaddrinfo(servinfo);

	if(listen(socketfd, BACKLOG) == -1)  //listens for incoming connections
		return -1;

	return 0;
}

int strToInt(const char* s)
{ //Converts the String to Integer; used majorly to convert char port number to int
	int ret = 0;
	int i = 0;
	while(i<strlen(s))
	{
		int t = s[i]-'0';
		if  (t<0 || t >9) 
			return -1;
		ret = ret*10+t;
		i++;
	}
	return ret;
}

void packClientInfo(char *list)  //Packs the client Info in one string
{
	int i = 0;
	while ( i < hostIndex ) 
	{
		if(hosts[i].status == login)
		{
			char status[5];			
			char temp[PORTSTRLEN];
			
			sprintf(temp, "%d", hosts[i].portNum);
			sprintf(status, "%d", hosts[i].status);

			// Packing data in list
			strcat(list, hosts[i].hostname);
			strcat(list, "---");
			strcat(list, hosts[i].ip_addr);
			strcat(list, "---");
			strcat(list, temp);
			strcat(list, "---");
			strcat(list, status);
			strcat(list, "---");
		}

		i++;
	}
}

void unpack_store(char *list)  //unpacks the list and stores it locally
{
	char *parts[20];
	
	char *p;
	
	int count = 0;
	for (p = strtok(list, "---"); p != NULL; p = strtok(NULL, "---"))  //unpacks the packed list
	{
		parts[count++] = p;		
	}

	if (hostIndex != 0) //reset to 0 to initiate filling the data 
		hostIndex = 0;
	
	int i = 0;
	while(i<count) //stores the info for each client in the local list
	{
		strcpy(hosts[hostIndex].hostname, parts[i++]);
		strcpy(hosts[hostIndex].ip_addr, parts[i++]);
		int tmp = strToInt(parts[i++]);
		hosts[hostIndex].portNum = tmp;
		tmp = strToInt(parts[i++]);
		hosts[hostIndex++].status = tmp;
	}

}

int isBlocked(int sender, char *receiver)
{
	// Check if certain sender is blocked by receiver  1 -> BLOCKED ,  0->UNBLOCKED
	char sender_ip[INET_ADDRSTRLEN] = "";
	int i = 0;

	while(i<hostIndex)   //fetch sender IP address
	{
		if(hosts[i].hostsockfd == sender)
		{
			strcpy(sender_ip, hosts[i].ip_addr);
			break;
		}
		i++;
	}

	i = 0;

	int ret = 0;
	while(i<hostIndex)   //check if its in the receivers blockedIPs list
	{
		if(strcmp(hosts[i].ip_addr, receiver) == 0)
		{
			int j = 0;
			while(j <hosts[i].blockindex)
			{
				if(strcmp(hosts[i].blockedIPs[j]->ip_addr, sender_ip) == 0)
				{
					ret = 1;
					break;
				}

				j++;
			}
			break;
		}

		i++;
	}

	return ret;
}

//This function handles the commands entered throgh command line interface 
void shellCmds(char **cmd, int count)
{

	if (strcmp(cmd[0], "AUTHOR") == 0) 
	{
		cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);
		char your_ubit_name[9] = "ameynare";		
		cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", your_ubit_name);		
		cse4589_print_and_log("[%s:END]\n", cmd[0]);		
	}
	
	else if(strcmp(cmd[0], "IP") == 0){
		get_IP();    //print and log statements are handled in the function get_IP()		
	}

	else if(strcmp(cmd[0], "PORT") == 0)
	{
		cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);		
		cse4589_print_and_log("PORT:%d\n", strToInt(lis_port));		
		cse4589_print_and_log("[%s:END]\n", cmd[0]);		
	}
	
	else if(strcmp(cmd[0], "LIST") == 0)
	{
		int index = 1;
		cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);
		//loop to print the client details from the stored struct data structure
		int i = 0;		
		while(i<hostIndex)
		{
			if( login == hosts[i].status)
				cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", index++, hosts[i].hostname, hosts[i].ip_addr, hosts[i].portNum);	
				//prints the client details one by one	
			i++;
		}
		cse4589_print_and_log("[%s:END]\n", cmd[0]);
	}
	
	else if(strcmp(cmd[0], "REFRESH") == 0)
	{
		if(isServer != 0 || !logedin)  //Needs client to be logged in
		{
			//on failure
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
			return;
		}

		send(clientsockfd, "REFRESH", 7, 0);  //send msg to the server for refresh list of currenlty logged-in clients
		char update[BUFLEN];
		recv(clientsockfd, update, BUFLEN, 0);  //server sends list of currently logged in clients
		unpack_store(update);                   //unpack and store the details from the list in the data structure 
		cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);		
		cse4589_print_and_log("[%s:END]\n", cmd[0]);
		
	}

	else if (strcmp(cmd[0], "BROADCAST") == 0)
	{
		if (isServer != 0 || !logedin)  //Needs logged in client
		{
			//on failure
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
			return;
		}

		//Generating the msg entered on the terminal
		char msgbody[MSGLEN] = "";
		int i = 1;
		while (i<count)
		{
			strcat(msgbody, cmd[i]);
			if(i != count-1) 
				strcat(msgbody, " ");
			i++;
		}
		//Generating the command entered on the terminal
		char tercmd[BUFLEN];
		strcpy(tercmd, cmd[0]);
		strcat(tercmd, " ");
		strcat(tercmd, msgbody);
		send(clientsockfd, tercmd, BUFLEN, 0);  ////send the command to the server
		cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);		
		cse4589_print_and_log("[%s:END]\n", cmd[0]);
		
	}
		
	else if(strcmp(cmd[0], "SEND") == 0)
	{
		if( !is_valid_IP(cmd[1]) || !logedin ||  isServer != 0 )
		{
			//on failure
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
			return;
		}

		
		int present = 0;
		int i = 0;
		while (i<hostIndex)   //Check the receiver is in the local list of the sender
		{
			if (strcmp(cmd[1], hosts[i].ip_addr) == 0) 
			{
				present = 1; //present in local list
				break;
			}
			i++;
		}
		
		if(present == 0) //receiver is not in the local list of the sender
		{
			//on failure
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);
			
			return;
		}

		char msg[MSGLEN] = "";
		i = 2;
		while (i<count)  // loop concatenates each chunk of sent msg to the char msg
		{
			strcat(msg, cmd[i]);
			if(i != count-1) 
				strcat(msg, " ");
			i++;
		}

		//Generating the command entered on the terminal
		char buf[BUFLEN] = "";
		strcat(buf, cmd[0]);
		strcat(buf, " ");
		strcat(buf, cmd[1]);
		strcat(buf, " ");
		strcat(buf, msg);
		send(clientsockfd, buf, sizeof(buf), 0);  //send msg to the server

		char result[10];
		recv(clientsockfd, result, 10, 0);  //response from the server
		if (strcmp(result, "FAIL") == 0) 
		{
			//on failure
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
		}
		
		else
		{
			//on success
			cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
		}

	}

	else if(strcmp(cmd[0], "BLOCKED") == 0)
	{
		if(isServer != 1 || count != 2 || !is_valid_IP(cmd[1]))
		{
			//on failure
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);		
			cse4589_print_and_log("[%s:END]\n", cmd[0]);		
			return;
		}

		int flag = 0, i= 0;
		while(i<hostIndex)
		{
			if(strcmp(hosts[i].ip_addr, cmd[1]) == 0)
			{ // fetching the clients struct host
				flag = 1;
				cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);
				
				for (int j=0; j<hosts[i].blockindex; j++)
				{ //looping through the block clients struct in the host struct
					cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", j+1, hosts[i].blockedIPs[j]->hostname, hosts[i].blockedIPs[j]->ip_addr, hosts[i].blockedIPs[j]->portNum);					
				}
				break;
			}
			i++;
		}

		if(flag == 0)
		{
			//on failure
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);		
			cse4589_print_and_log("[%s:END]\n", cmd[0]);		
			return;
		}
		
		else
		{
			cse4589_print_and_log("[%s:END]\n", cmd[0]);
		
		}
	}

	else if(strcmp(cmd[0], "BLOCK") == 0)
	{
		if (isServer != 0 || !logedin || !is_valid_IP(cmd[1]) || count != 2) 
		{
			//on failure
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
			return;
		}

		// Checking for IP address match in local list
		int flag = 0;
		int i = 0;
		while(i<hostIndex)
		{
			if(strcmp(hosts[i].ip_addr, cmd[1]) == 0)
			{
				flag = 1;  //present in local list
				break;
			}
			i++;
		}

		if(flag == 0)  //Not in local list
		{
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
			return;
		}

		//Generating the command entered on the terminal
		char tercmd[BUFLEN];
		strcpy(tercmd, cmd[0]);
		strcat(tercmd, " ");
		strcat(tercmd, cmd[1]);
		send(clientsockfd, tercmd, BUFLEN, 0);

		char res[10];  
		recv(clientsockfd, res, 10, 0); //response from the receiver
		if(strcmp(res, "FAIL") == 0)
		{
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
		}
		
		else
		{
			//success
			cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);
			
		}

	}
	
	else if(strcmp(cmd[0], "UNBLOCK") == 0)
	{
		if(isServer != 0 || !logedin || !is_valid_IP(cmd[1]) || count != 2)
		{
			//on failure
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
			return;
		}

		// Checking for IP address match in local list
		int flag = 0;
		int i = 0;
		while(i<hostIndex)
		{
			if(strcmp(hosts[i].ip_addr, cmd[1]) == 0)
			{
				flag = 1;
				break;
			}
			i++;
		}
		
		if(flag == 0)
		{
			//fail
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
			return;
		}

		//Generating the command entered on the terminal
		char tercmd[BUFLEN];
		strcpy(tercmd, cmd[0]);
		strcat(tercmd, " ");
		strcat(tercmd, cmd[1]);
		send(clientsockfd, tercmd, BUFLEN, 0);

		char res[10];  //result from the server
		recv(clientsockfd, res, 10, 0);
		if(strcmp(res, "FAIL") == 0)
		{
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
		}
		
		else
		{
			//success
			cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
		}

	}

	else if(strcmp(cmd[0], "LOGOUT") == 0)
	{
		if(!logedin)  //if logged in already
		{
			//fail
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);		
			cse4589_print_and_log("[%s:END]\n", cmd[0]);		
			return;
		}

		char buf[BUFLEN] = "LOGOUT";
		send(clientsockfd, buf, BUFLEN, 0);  //send the command to the server
		logedin = 0;   //logged-out
		close(clientsockfd);  //close the socket
		FD_CLR(clientsockfd, &master_list);   //clear closed socket from master list
		cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);		
		cse4589_print_and_log("[%s:END]\n", cmd[0]);		

	}

	else if(strcmp(cmd[0], "LOGIN") == 0)
	{ 
		if(isServer || count != 3 || !is_valid_IP(cmd[1]) || !is_valid_port(cmd[2]) || logedin)
		{
			// only when fails to meet the required conditions
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);					
			return;
		}

		int server_port = atoi(cmd[2]); 
		//int socketfd; 
		struct sockaddr_in server_addr, client_addr;
		clientsockfd = socket(AF_INET, SOCK_STREAM, 0);   //create socket
		if (clientsockfd < 0) 
		{ 
			perror("socket() failed\n"); 
		}
				
		bzero(&server_addr, sizeof(server_addr));
		server_addr.sin_family = AF_INET;
		inet_pton(AF_INET, cmd[1], &server_addr.sin_addr);
		server_addr.sin_port = htons(server_port);

		if(connect(clientsockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
		{
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);
			cse4589_print_and_log("[%s:END]\n", cmd[0]);
			return; 
		}
				
		send(clientsockfd, lis_port, sizeof lis_port, 0); //sends port number to the server to fetch its buffered messages and list of logged-in clients 

		// Stores the data provided by server on successful registration
		char clientList[BUFLEN];
		recv(clientsockfd, clientList, BUFLEN, 0);  //receives the list of logged-in clients from the server
		unpack_store(clientList);                 

		char bufmsgList[BUFLEN];
		recv(clientsockfd, bufmsgList, BUFLEN, 0);  //receives the list of buffered msgs from the server

		char *msgbuf[BUFLEN];  //messages are separated are stored
		int count = 0;
		char *q = strtok(bufmsgList, "---");
		while (q!=NULL) 
		{
			msgbuf[count++] = q;
			q = strtok(NULL, "---");
		}
		
		int i = 1;
		//prints the buffered messges one by one
		while( i<count )
		{   
			char *client_ip = msgbuf[i];
			char *client_msg = msgbuf[2];
			cse4589_print_and_log("[%s:SUCCESS]\n", "RECEIVED");			
			cse4589_print_and_log("msg from:%s\n[msg]:%s\n", client_ip, client_msg);			
			cse4589_print_and_log("[%s:END]\n", "RECEIVED");			
			i+=2;
		}

		logedin = 1;
		FD_SET(clientsockfd, &master_list);
		maxfd = clientsockfd>maxfd? clientsockfd:maxfd;   //set maxfd to max of the two

		cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);		
		cse4589_print_and_log("[%s:END]\n", cmd[0]);
		
	}
	
	else if(strcmp(cmd[0], "EXIT") == 0)
	{
		char buf[BUFLEN] = "EXIT";
		send(clientsockfd, buf, BUFLEN, 0);   //sends command to the server
		logedin = 0;
		close(clientsockfd); //close socket
		FD_CLR(clientsockfd, &master_list);  //clear from master list
		cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);		
		cse4589_print_and_log("[%s:END]\n", cmd[0]);		
		exit(0);
	}
		
	else if(strcmp(cmd[0], "STATISTICS") == 0)
	{
		if(isServer != 1)
		{
			//fail
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);		
			cse4589_print_and_log("[%s:END]\n", cmd[0]);		
			return;
		}
		
		cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);

		int i = 0;
		while(i<hostIndex)
		{
			char tmp[20];
			if(hosts[i].status == login)
				strcpy(tmp, "logged-in");
			
			else
				strcpy(tmp, "logged-out");

			cse4589_print_and_log("%-5d%-35s%-8d%-8d%-8s\n", i+1, hosts[i].hostname, hosts[i].msg_sent, hosts[i].msg_received, tmp);  //prints the list of logged in and looged out clients with msgs sent and received
			i++;	
		}
		
		cse4589_print_and_log("[%s:END]\n", cmd[0]);
	}

}


// Server response to client incoming msges

void server_response(char **arguments, int count, int calling_client)
{  
	if(strcmp(arguments[0], "SEND") == 0)
	{

		char msg[BUFLEN] = "";
		char sender_ip[INET_ADDRSTRLEN];
		int sender= 0;
		while(sender<hostIndex)
		{
			if(hosts[sender].hostsockfd == calling_client)  //identifying sender
			{
				strcat(msg, hosts[sender].ip_addr);
				strcat(msg, " ");
				strcat(msg, arguments[2]);
				strcat(msg, " ");

				strcpy(sender_ip, hosts[sender].ip_addr);  //fetch sender ipaddr
				break;
			}
			sender++;
		}

		int present = 0, i = 0; //indicates already exited
		while(i<hostIndex)
		{
			if(strcmp(arguments[1], hosts[i].ip_addr) == 0)
			{
				present = 1;
				if(isBlocked(calling_client, arguments[1]))  //check if blocked
				{
					send(calling_client, "BLOCKED", 7, 0);
					return;
				}

				if(hosts[i].status == login)  
				{
					send(hosts[i].hostsockfd, msg, BUFLEN, 0);
					hosts[i].msg_received++;
					//triger event
					cse4589_print_and_log("[%s:SUCCESS]\n" , "RELAYED");					
					cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", hosts[sender].ip_addr, hosts[i].ip_addr, arguments[2]);					
					cse4589_print_and_log("[%s:END]\n", "RELAYED");					

				}
				
				else
				{
					strcat(bufferedmsg, hosts[i].ip_addr);
					strcat(bufferedmsg, "---");
					strcat(bufferedmsg, sender_ip);
					strcat(bufferedmsg, "---");
					strcat(bufferedmsg, arguments[2]);
					strcat(bufferedmsg, "---");
					hosts[i].msg_received++;
				}
				break;
			}

			i++;
		}

		if(present==0)
			send(calling_client, "FAIL", 4, 0);
		
		else
		{
			send(calling_client, "SUCCESS", 7, 0);
			hosts[sender].msg_sent++;
		}

	}
	
	else if(strcmp(arguments[0], "REFRESH") == 0)
	{
		char clientList[BUFLEN] = ""; 
		packClientInfo(clientList);   //packs the client info in list
		send(calling_client, clientList, BUFLEN, 0);  //sends its back to the client
	}

	else if(strcmp(arguments[0], "BROADCAST") == 0)
	{
		char sender_ip[INET_ADDRSTRLEN];
		char msg[BUFLEN];
		int i = 0;
		while (i< hostIndex)
		{
			if(calling_client == hosts[i].hostsockfd )
			{
				hosts[i].msg_sent++;
				strcpy(sender_ip, hosts[i].ip_addr);
				strcpy(msg, hosts[i].ip_addr);
				strcat(msg, " ");
				strcat(msg, arguments[1]);
				strcat(msg, " ");
			}
			i++;
		}

		i = 0;
		// server broadcast the msg to all linked clients. sends msg to logged-in clients and buffers for logged-out clients
		while ( i < hostIndex )
		 {
			if(!isBlocked(calling_client, hosts[i].ip_addr) && (hosts[i].hostsockfd != calling_client))
			{
				if(hosts[i].status == login)
				{
					send(hosts[i].hostsockfd, msg, BUFLEN, 0); //sending to logged-in target
					hosts[i].msg_received++;
					//triger event
					cse4589_print_and_log("[%s:SUCCESS]\n" , "RELAYED");					
					cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", sender_ip, "255.255.255.255", msg);					
					cse4589_print_and_log("[%s:END]\n", "RELAYED");
					
				}
				
				else
				{
					strcat(bufferedmsg, hosts[i].ip_addr);   //buffering for logged-out target
					strcat(bufferedmsg, "---");
					strcat(bufferedmsg, sender_ip);
					strcat(bufferedmsg, "---");
					strcat(bufferedmsg, arguments[1]);
					strcat(bufferedmsg, "---");
					hosts[i].msg_received++;
				}
			}
		}
	}
	
	else if(strcmp(arguments[0], "BLOCK") == 0)
	{

		int t = 0;
		while(t<hostIndex)
		{
			if(hosts[t].hostsockfd == calling_client) 
				break;
			t++;
		}

		int found = 0;
		int b = 0;
		while ( b < hostIndex )
		{
			if(strcmp(hosts[b].ip_addr, arguments[1])== 0)   //checks if the sender is exited or not
			{
				found = 1; // sender not exited
				break;
			}
			b++;
		}

		if(found == 0)
		{
			send(calling_client, "FAIL", 4, 0);  //sends back fail if sender client exited
			return;
		}

		if (hosts[t].blockindex == 0) 
			hosts[t].blockedIPs[hosts[t].blockindex++] = &hosts[b];  //directly append to the structure
		
		else
		{
			int i = 0;
			while(i<hosts[t].blockindex)
			{
				if(strcmp(hosts[t].blockedIPs[i]->ip_addr, arguments[1]) == 0)  //sender client is already blocked
				{
					send(calling_client, "FAIL", 4, 0);
					return;
				}
				i++;
			}
			hosts[t].blockedIPs[hosts[t].blockindex++] = &hosts[b];

			//sort the block list in increasing order of port number
			if(hosts[t].blockindex > 1)
			{
				int i = 0;
				while(i<hosts[t].blockindex-1)
				{
					int j = i;
					while( j<hosts[t].blockindex ) 
					{
						if(hosts[t].blockedIPs[i]->portNum > hosts[t].blockedIPs[j]->portNum)
						{
							struct host *tmp = hosts[t].blockedIPs[i];
							hosts[t].blockedIPs[i] = hosts[t].blockedIPs[j];
							hosts[t].blockedIPs[j] = tmp;
						}
						j++;
					}

					i++;
				}
			}
		}
		send(calling_client, "SUCCESS", 7, 0);  

	}
	
	else if(strcmp(arguments[0], "UNBLOCK") == 0)
	{
		int t = 0;
		while( t<hostIndex)
		{
			if(hosts[t].hostsockfd == calling_client)  
				break;
			t++;
		}

		if(hosts[t].blockindex == 0)
		{
			send(calling_client, "FAIL", 4, 0);
			return;
		}

		int flag = 0, i = 0;
		while(i<hosts[t].blockindex)
		{
			if(strcmp(hosts[t].blockedIPs[i]->ip_addr, arguments[1]) == 0)
			{
				if(i == 2)   //Check if the last blocked client is unblocked
				{
					hosts[t].blockindex--;
					flag = 1;
					break;
				}
				// shift the blocked clients upwards if any of the middle clients is unblocked
				for(int j=i+1;j<hosts[t].blockindex;j++)
				{
					hosts[t].blockedIPs[j-1] = hosts[t].blockedIPs[j];
				}
				flag = 1;
				hosts[t].blockindex--;
				break;
			}
			i++;
		}
		
		if(flag == 0)
		{
			send(calling_client, "FAIL", 4, 0);
			return;
		}
		send(calling_client, "SUCCESS", 7, 0);

	}
	
	else if(strcmp(arguments[0], "EXIT") == 0)
	{
		int t = 0;
		while(t<hostIndex)
		{
			if(hosts[t].hostsockfd == calling_client)
			{
				close(hosts[t].hostsockfd);
				FD_CLR(hosts[t].hostsockfd, &master_list);
				if(t == 3)  //last of the all 4 logged-in clients
				{
					hostIndex--;
					break;
				}

				int j = t + 1;
				while(j<hostIndex)
				{
					hosts[j-1] = hosts[j];  //removes the details of the exited client and shift up the list
					j++;
				}
				hostIndex--;

				break;
			}

			t++;
		}
	}
	
	else if(strcmp(arguments[0], "LOGOUT") == 0)
	{
		int i = 0;
		while(i<hostIndex)
		{
			if(hosts[i].hostsockfd == calling_client)
			{
				close(hosts[i].hostsockfd);      // close socket
				FD_CLR(hosts[i].hostsockfd, &master_list);  //clear from master_list
				hosts[i].status = logout;
				break;
			}
			i++;
		}
	}


}

void initiate(void)
{
	char *argm[5];

	// Initializes file descripter to have zero bits
	FD_ZERO(&master_list);
	FD_ZERO(&watch_list);
	FD_SET(STD_IN, &master_list);
	FD_SET(socketfd, &master_list);
	maxfd = socketfd;

	while (1) 
	{
		watch_list = master_list;
		// select() ->  indicates which of the specified file descriptors is ready for reading, blocks if none is ready
		if(select(maxfd+1, &watch_list, NULL, NULL, NULL) == -1)
			return;

		int i = 0;
		while( i < maxfd+1 )
		{
			if(FD_ISSET(i, &watch_list))
			{
				if(i == STD_IN)
				{
					char *cmd = (char *)malloc(sizeof(char)*CMD_LEN);
					memset(cmd, '\0', CMD_LEN);
					fgets(cmd, CMD_LEN-1, stdin);
					int j = 0;
					while( j < CMD_LEN )
					{
						if(cmd[j] == '\n')
						{
							cmd[j] = '\0';
							break;
						}
						j++;
					}

					int count = 0;
					for(char *tmp = strtok(cmd, " "); tmp != NULL; tmp = strtok(NULL, " "))
					{
						argm[count++] = tmp;    //argm stores all the parts of input provided through terminal
						
					}

					shellCmds(argm, count);    //user defined function that implements set of events

				}
				
				else if(i == socketfd && isServer == 1)  //In server mode
				{
					// process new hosts, use a data structure to store info
					struct sockaddr_storage remoteaddr;
					socklen_t len = sizeof(remoteaddr);
					int newfd = accept(socketfd, (struct sockaddr *)&remoteaddr, &len);
					
					if(newfd == -1)
						continue;

					FD_SET(newfd, &master_list);
					maxfd = maxfd > newfd? maxfd: newfd;

					char clientPort[PORTSTRLEN];
					recv(newfd, clientPort, PORTSTRLEN, 0);
					char tmp[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &(((struct sockaddr_in *)&remoteaddr)->sin_addr), tmp, INET_ADDRSTRLEN);
					struct hostent *he;
					struct in_addr ipv4addr;
					inet_pton(AF_INET, tmp, &ipv4addr);
					he = gethostbyaddr(&ipv4addr, sizeof(struct in_addr), AF_INET);   ////returns data in hostent structure
					int exist = 0;
					for(int i=0;i<hostIndex;i++)
					{
						if(strcmp(hosts[i].ip_addr, tmp) == 0) //checks if any of the conections have same addr and updates the existing
						{
							exist = 1;
							hosts[i].status = login;
							break;
						}
					}
					//if not match found, maintain a new host record
					if(!exist)
					{
						struct host newhost;
						newhost.hostsockfd = newfd;
						strcpy(newhost.ip_addr, tmp);
						newhost.portNum = strToInt(clientPort);
						strcpy(newhost.hostname, he->h_name);
						newhost.msg_sent = 0;
						newhost.msg_received = 0;
						newhost.status = login;
						newhost.blockindex = 0;
						hosts[hostIndex++] = newhost;   //append to our previous host set
					}

					// Sorting the connection array in increasing order of the port number
					if(hostIndex > 1)
					{
						for(int cur = 0; cur< hostIndex-1; cur++)
						{
							for(int fast = cur+1; fast<hostIndex; fast++)
							{
								if(hosts[cur].portNum > hosts[fast].portNum)
								{
									struct host tmp = hosts[cur];
									hosts[cur] = hosts[fast];
									hosts[fast] = tmp;
								}
							}
						}
					}

					//1. sents packed list of current logged-in clients to the newly connected client
					char list[BUFLEN] = "";
					packClientInfo(list);
					send(newfd, list, BUFLEN, 0);


					//2. Prepare buffered msg for that client
					int count = 0;
					char *bufmsg[BUFLEN];
					char *p;
					p = strtok(bufferedmsg, "---");
					while (p!=NULL) 
					{
						bufmsg[count++] = p;
						p = strtok(NULL, "---");
					}

					char newBufmsg[BUFLEN]="";
					char msgtosend[BUFLEN]="";

					int i = 0, flag = 0;
					while ( i < count ) 
					{
						if (strcmp(tmp, bufmsg[i]) == 0) { //matching the IP address in the msg with the cient
							if(flag == 0){
								 strcat(msgtosend, "BROADCAST,");
								 strcat(msgtosend, "---");
								 flag = 1;
							 }
                             strcat(msgtosend, bufmsg[i+1]);  //generating buffered msg for the client
                             strcat(msgtosend, "---");
                             strcat(msgtosend, bufmsg[i+2]);
                             strcat(msgtosend, "---");
							 cse4589_print_and_log("[%s:SUCCESS]\n", "RELAYED");
							 cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", bufmsg[i+1], bufmsg[i], bufmsg[i+2]);
							 cse4589_print_and_log("[%s:END]\n", "RELAYED");
							 i+=3;
						}
						else if(strcmp(bufmsg[i], "255.255.255.255") == 0) //means its broadcasted mesage
						{
							if(flag == 0)
							{
								strcat(msgtosend, "BROADCAST,");
								strcat(msgtosend, "---");
								flag = 1;
							}
							strcat(newBufmsg, "255.255.255.255");  //generating buffered msg for the client
							strcat(newBufmsg, "---");
							strcat(newBufmsg, bufmsg[i+1]);
							strcat(newBufmsg, "---");
							strcat(newBufmsg, bufmsg[i+2]);
							strcat(newBufmsg, "---");

							strcat(msgtosend, bufmsg[i+1]);
							strcat(msgtosend, "---");
							strcat(msgtosend, bufmsg[i+2]);
							strcat(msgtosend, "---");
							cse4589_print_and_log("[%s:SUCCESS]\n", "RELAYED");							
							cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", bufmsg[i+1], bufmsg[i], bufmsg[i+2]);		
							cse4589_print_and_log("[%s:END]\n", "RELAYED");
							
							i+=3;
						}										
						else
						{// buffer holds remaining msgs of other clients
							strcat(newBufmsg, bufmsg[i++]);
							strcat(newBufmsg, "---");
							strcat(newBufmsg, bufmsg[i++]);
							strcat(newBufmsg, "---");
							strcat(newBufmsg, bufmsg[i++]);
							strcat(newBufmsg, "---");
						}
					}
					strcpy(bufferedmsg, newBufmsg); //copy back to original buffer
			
					send(newfd, msgtosend, BUFLEN, 0); 
				}
				
				else if( i == clientsockfd && isServer == 0 )  //In client mode
				{
					char buf[BUFLEN];
					int databytes = recv(i, buf, sizeof buf, 0);
					
					char flag[10]="";

					if(databytes > 1)
						strncpy(flag, buf, 10);  // copies only upto 10 characters

					if(strcmp(flag, "BROADCAST,") == 0)
					{
						char *tmp;
						int count = 0;
						char *msgset[BUFLEN];
						tmp = strtok(buf, "---");
						// for (tmp = strtok(buf, "---"); tmp != NULL; tmp = strtok(NULL, "---")) 
						// {
						// 	msgset[count++] = tmp;
						// }
						while (tmp != NULL) {
	 						msgset[count++] = tmp;
	 						tmp = strtok(NULL, "---");
	 					}			
						
						//prints and logs the msgs on the client side
						int i = 1;
						while ( i < count )
						{
							cse4589_print_and_log("[%s:SUCCESS]\n", "RECEIVED");							
							cse4589_print_and_log("msg from:%s\n[msg]:%s\n", msgset[i], msgset[i+1]);							
							cse4589_print_and_log("[%s:END]\n", "RECEIVED");
							
							i+=2;
						}

					}					
					else
					{
						char *tmp;
						int count = 0;
						char *msgset[BUFLEN];
						tmp = strtok(buf, " ");
						while (tmp != NULL) {
	                         msgset[count++] = tmp;
	                         tmp = strtok(NULL, " ");
	                     }

						char recvmsg[MSGLEN] = "";
						int n = 1;
						while( n < count )
						{
							strcat(recvmsg, msgset[n]);
							if(n<count-1) strcat(recvmsg, " ");
							n++;
						}

						cse4589_print_and_log("[%s:SUCCESS]\n", "RECEIVED");						
						cse4589_print_and_log("msg from:%s\n[msg]:%s\n", msgset[0], recvmsg);						
						cse4589_print_and_log("[%s:END]\n", "RECEIVED");
							
					}
				}
										
				else
				{
					char buf[BUFLEN];
					ssize_t databytes = recv(i, buf, sizeof buf, 0);
					buf[databytes] = '\0';

					int count = 0;
					char *p;
					char *arguments[BUFLEN];
					for (p = strtok(buf, " "); p != NULL; p = strtok(NULL, " ")) 
					{
						arguments[count++] = p;
						
					}

					char msg[MSGLEN] = "";
					if(strcmp(arguments[0], "SEND") == 0)  //separating msgs and command
					{
						int i = 2;
						while( i < count )
						{
							strcat(msg, arguments[i]);
							
							if(i < count-1) 
								strcat(msg, " ");

							i++;
						}
						count = 3;
						arguments[count-1] = msg;
					}

					if(strcmp(arguments[0], "BROADCAST") == 0)   //separating msgs and command
					{
						int i = 1;
						while( i < count )
						{
							strcat(msg, arguments[i]);
							if(i < count-1) {
								strcat(msg, " ");
							}
							i++;
						}
						count = 2;
						arguments[count-1] = msg;
					}					

					server_response(arguments,count, i); //call to the server to give response to client calls

				}
			}
			i++;
		}
	}
}



