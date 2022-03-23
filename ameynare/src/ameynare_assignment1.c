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
//#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
//#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
//#include <sys/wait.h>
//#include <signal.h>
#include <sys/select.h>

#include "../include/global.h"
#include "../include/logger.h"
#include "../src/logger.c"

#define CMD_SIZE 100
#define BUFLEN 1024
#define MSGLEN 256
#define BACKLOG 4
#define STD_IN 0
#define HOSTNAMESTRLEN 50
#define PORTSTRLEN 10
#define logged_in 1
#define logged_out 0


struct connection {
	char hostname[HOSTNAMESTRLEN];
	char remote_addr[INET_ADDRSTRLEN];
	int portNum;
	int msg_received;
	int msg_sent;
	int status;
	int blockindex;

	struct connection *blockedIPs[3];

	int connsockfd;
};

char bufferedmsg[BUFLEN] = "";

int isClient = 0;   //// This a variable is used as a flag to indicate client or server. 0 -> Server and 1 -> Client
int localsockfd;
int clientsockfd;
//int flag = 0;
char listenerPort[PORTSTRLEN]; 
struct connection connections[4];
int connIndex = 0;
int loggedin = 0; // a flag to indicate log in, avoid multiple log in

fd_set master, read_fds;
int maxfd;

/*
*Function to get local IP address,
*returns 0 on success and -1 on fail.
*Pass in a char * to store the result.
*/


/*-----------------------HELPER FUNCTIONS-----------------------*/
int is_valid_port(char *input) {
	int i = 0;
	if(input[i] == '-') { return 0; }
	for(; input[i] != '\0'; i++) {
		if(!isdigit(input[i])) return 0;
	}
	return 1;
}

int is_valid_IP(char *ip) { 	
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

int bind_socket(char port_str)
{	
	if(!is_valid_port(port_str)){
		perror("Invalid Port Number entered!")
	}
	int port = atoi(port_str);  //Converts the port from char to int

	struct sockaddr_in my_addrs;
	int fdsocket = 0;
	fdsocket = socket(AF_INET, SOCK_STREAM, 0);// return socket file descriptor
    if(fdsocket < 0)
    {
       perror("Failed to create socket");
       return 0;
    }

    //setting up client socket
    my_addrs.sin_family=AF_INET;
    my_addrs.sin_addr.s_addr=INADDR_ANY;
    my_addrs.sin_port=htons(port);
    int optval=1;
    setsockopt(fdsocket, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    if(bind(fdsocket, (struct  sockaddr*) &my_addrs, sizeof(struct sockaddr_in)) == 0)
    {
    	printf("\nclient binded to port correctly\n");
    	return fdsocket;
    }
    else
    {
    	printf("\nError in binding client port\n");
    	return 0;
    }
}

int connect_host(char *server_ip, char *server_port)
{
    struct addrinfo hints, *servinfo, *p;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if(getaddrinfo(server_ip, server_port, &hints, &servinfo) != 0){
		//fails to get the addr info
		cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
		cse4589_print_and_log("[%s:END]\n", cmd[0]);			
		return;
	}
	for(p=servinfo; p!= NULL; p=p->ai_next){
		if((clientsockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
			continue;
		}
		if(connect(clientsockfd, p->ai_addr, p->ai_addrlen) == -1){
			close(clientsockfd);
			continue;
		}
		break;
	}
	if(p == NULL){
		//fail
		cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
		cse4589_print_and_log("[%s:END]\n", cmd[0]);			
		return;
	}
	freeaddrinfo(servinfo);
    return clientsockfd;
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

int strToNum(const char* s){
	int ret = 0;
	for (int i=0;i<strlen(s);i++){
		int t = s[i]-'0';
		if  (t<0 || t >9) return -1;
		ret = ret*10+t;
	}
	return ret;
}

// check if receiver of the msg is in local list of the client
int in_Cur_LogClients(char *rcv_client_ip){
	int present = 0;
	for (int i=0; i<connIndex; i++) {
		if (strcmp(rcv_client_ip, connections[i].remote_addr) == 0) {
			present = 1;
			break;
		}
	}
	return present;
}

// target_ip is client to check if blocked in for client having recvsockfd
int alreadyBlocked(char *target_ip, int recvsockfd){
	in result = 0;
	for(int i =0; i<connIndex; i++){
		if(connections[i].connsockfd == recvsockfd){
			for(int j=0; j <connections[i].blockindex;j++){
				if(strcmp(connections[i].blockedIPs[j]->remote_addr, target_ip) == 0){
					result = 1;
					break;
				}
			}
			break;
		}
	}	
}

// check if receiver has blocked the sender 
int isBlocked(int sender_, char *receiver){
	int ret = 0;

	char senderaddr[INET_ADDRSTRLEN] = "";
	for(int i=0;i<connIndex;i++){
		if(connections[i].connsockfd == sender){
			strcpy(senderaddr, connections[i].remote_addr);
			break;
		}
	}
	for(int i =0; i<connIndex; i++){
		if(strcmp(connections[i].remote_addr, receiver) == 0){
			for(int j=0; j <connections[i].blockindex;j++){
				if(strcmp(connections[i].blockedIPs[j]->remote_addr, senderaddr) == 0){
					ret = 1;
					break;
				}
			}
			break;
		}
	}

	return ret;
}


// Need to remove this function, alternate function implemented get_IP
int get_localIP(char *res){
	int sockfd = 0;
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr myip;
	socklen_t len = sizeof(myip);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	if(getaddrinfo("8.8.8.8", "53", &hints, &servinfo) != 0){
		return -1;
	}

	for(p=servinfo; p!= NULL; p=p->ai_next){
		if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
			continue;
		}

		if(connect(sockfd, p->ai_addr, p->ai_addrlen) == -1){
			close(sockfd);
			continue;
		}
		break;
	}

	if(p == NULL){
		return -1;
	}
	freeaddrinfo(servinfo);

	getsockname(sockfd, &myip, &len);
	inet_ntop(AF_INET, &(((struct sockaddr_in *)&myip)->sin_addr), res, INET6_ADDRSTRLEN);
	close(sockfd);

	return 0;
}

/*
* Preparation, create socket and listen for connection.
* Success return 0, otherwise -1
*/

// Need to remove this function, separate functions implemented for server and client
int prep(const char *port){
	struct addrinfo hints, *servinfo, *p;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if(getaddrinfo(NULL, port, &hints, &servinfo) == -1){
		return -1;
	}

	for(p = servinfo; p != NULL; p=p->ai_next){
		if((localsockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
			continue;
		}

		if(bind(localsockfd, p->ai_addr, p->ai_addrlen) == -1){
			close(localsockfd);
			continue;
		}
		break;
	}

	if(p == NULL) return -1;
	freeaddrinfo(servinfo);

	if(listen(localsockfd, BACKLOG) == -1){
		return -1;
	}

	return 0;
}



/*
* Check if given addr and #port is valid
*/
// Need to remove this function, separate functions implemented for server and client
int isValidAddr(char *addr, char *port){
	//debug
	//addr[strlen(addr)] = '\0';
	//port[strlen(port)] = '\0';
	int ret = 1;
	for(int i=0; i<CMD_SIZE;i++){
		if(*(addr+i) == '\0') break;
		if(*(addr+i) == '.') continue;
		int t = *(addr+i) - '0';
		if(t<0 || t>9) {
			ret = 0;
			break;
		}
	}

	for(int i=0; i<CMD_SIZE;i++){
		if(*(port+i) == '\0') break;
		int t = *(port+i) - '0';
		if(t<0 || t>9) {
			ret = 0;
			break;
		}
	}
	return ret;
}

/*
* Pack & unpack the list info to send,
* argm list shoulb be empty string "",
* res store in an struct conns array
*/
void packClientInfo(char *list){
	for (int i=0; i<connIndex; i++) {
		if(connections[i].status == logged_in){
			char tmp[PORTSTRLEN];
			char status[5];
			
			sprintf(tmp, "%d", connections[i].portNum);   // stores the formatted output to the char buffer specified
			sprintf(status, "%d", connections[i].status);

			// Packing data in list
			strcat(list, connections[i].hostname);   
			strcat(list, "---");
			strcat(list, connections[i].remote_addr);
			strcat(list, "---");
			strcat(list, tmp);
			strcat(list, "---");
			strcat(list, status);
			strcat(list, "---");
		}
	}
}

// functions unpacks and stores locally the list of client info from the server
void unpack_store(char *list){
	char *parts[20];
	int count = 0;
	char *p;
	p = strtok(list, "---");
	while (p != NULL) {
		parts[count++] = p;
		p = strtok(NULL, "---");
	}

	if (connIndex != 0) connIndex = 0;  // starting from the first storage point
	for(int i=0;i<count;){
		strcpy(connections[connIndex].hostname, parts[i++]);
		strcpy(connections[connIndex].remote_addr, parts[i++]);
		int tmp = strToNum(parts[i++]);
		connections[connIndex].portNum = tmp;
		tmp = strToNum(parts[i++]);
		connections[connIndex++].status = tmp;
	}

}

/*
* Check if certain sender is blocked by receiver
* return 0 if not blocked
*/



/*
* executes input command
*/
void shellCmd(char **cmd, int count){
	
	if (strcmp(cmd[0], "AUTHOR") == 0) {
		cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);
		char your_ubit_name[9] = "ameynare";		
		cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", your_ubit_name);		
		cse4589_print_and_log("[%s:END]\n", cmd[0]);
		
	}else if(strcmp(cmd[0], "IP") == 0){
		get_IP();    //print and log statements are handled in the function get_IP()
		
	}else if(strcmp(cmd[0], "PORT") == 0){
		cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);		
		cse4589_print_and_log("PORT:%d\n", strToNum(listenerPort));		
		cse4589_print_and_log("[%s:END]\n", cmd[0]);
		
	}else if(strcmp(cmd[0], "LIST") == 0){
		if (isClient && !logged_in){
			// on failure
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
			return;
		}else{
			int count = 1;
			cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);
			//loop to print the client details from the stored struct data structure		
			for(int i=0;i<connIndex;i++){
				if(connections[i].status == logged_in){
					cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", count++, connections[i].hostname, connections[i].remote_addr, connections[i].portNum);				
				}
			}
			cse4589_print_and_log("[%s:END]\n", cmd[0]);
		}
		
		
	}else if(strcmp(cmd[0], "LOGIN") == 0){ //CHECK - Has some part to be handled on the server side
		if(isClient != 1 || count != 3 || !is_valid_IP(cmd[1]) || !is_valid_port(cmd[2]) || loggedin){
			// only when fails to meet the required conditions
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
			return;
		}

		clientsockfd = connect_host(cmd[1], cmd[2]);  //creates and connect socket to the server
		
		send(clientsockfd, listenerPort, sizeof listenerPort, 0); //sends port number to the server to fetch its buffered messages and list of logged-in clients 

		// Stores the data provided by server on successful registration
		char buf[BUFLEN];
		recv(clientsockfd, buf, BUFLEN, 0);  //receives the list of logged-in clients from the server
		unpack_store(buf);                 

		char unread[BUFLEN];
		recv(clientsockfd, unread, BUFLEN, 0);  //receives the list of buffered msgs from the server
		char *msgbuf[BUFLEN];
		int count = 0;
		char *q = strtok(unread, "---");
		while (q!=NULL) {
			msgbuf[count++] = q;
			q = strtok(NULL, "---");
		}
		for(int i=1;i<count; ){    //CHECK HERE why i=1, not 0
			char client_ip = msgbuf[i];
			char client_msg = msgbuf[2];
			cse4589_print_and_log("[%s:SUCCESS]\n", "RECEIVED");			
			cse4589_print_and_log("msg from:%s\n[msg]:%s\n", client_ip, client_msg);			
			cse4589_print_and_log("[%s:END]\n", "RECEIVED");			
			i+=2;
		}

		loggedin = 1;
		FD_SET(clientsockfd, &master);
		maxfd = clientsockfd>maxfd? clientsockfd:maxfd;   //set maxfd to max of the two

		cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);		
		cse4589_print_and_log("[%s:END]\n", cmd[0]);
		
	}else if(strcmp(cmd[0], "REFRESH") == 0){ //CHECKED - Has some part to be handled on the server side
		if(isClient != 1 || !loggedin){
			// on failure
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
			return;
		}

		send(clientsockfd, "REFRESH", 7, 0);  //send msg to the server for refresh list of currenlty logged-in clients
		char update[BUFLEN];
		recv(clientsockfd, update, BUFLEN, 0);  //server sends list of currently logged in clients
		unpack_store(update);   //unpack and store the details from the list in the data structure 
		cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);		
		cse4589_print_and_log("[%s:END]\n", cmd[0]);
		
		//process msg to update list
	}else if(strcmp(cmd[0], "SEND") == 0){ //CHECKED - Has some part to be handled on the server side
		if(isClient != 1 || !loggedin || !is_valid_IP(cmd[1]) || !in_Cur_LogClients(cmd[1])){
			//on failure
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
			return;
		}

		char msg[MSGLEN] = "";    //initialize a string of length 256
		// loop concatenates each chunk of sent msg to the string msg
		for (int i=2;i<count;i++){  
			strcat(msg, cmd[i]);
			if(i != count-1) strcat(msg, " ");
		}

		//Generating the command to be sent to the server for being to desired client
		char buf[BUFLEN] = "";
		strcat(buf, cmd[0]);
		strcat(buf, " ");
		strcat(buf, cmd[1]);
		strcat(buf, " ");
		strcat(buf, msg);
		send(clientsockfd, buf, sizeof(buf), 0);  //send msg to the server

		char res[10];
		recv(clientsockfd, res, 10, 0);  //response from the server
		//debug
		//printf("--%s--\n", res);
		if (strcmp(res, "FAIL") == 0) {
			//on failure
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
		}else{
			//on success
			cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
		}

	}else if (strcmp(cmd[0], "BROADCAST") == 0){ //CHECKED - Has some exceptions to be handled on the server side
		if (isClient != 1 || !loggedin) {
			//on failure
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
			return;
		}
//        if (count != 2) {   
			//CHECK we can also check the count of chunks in the command (will not work as the msg can be divided in n chunks)
//            //fail
//            return;
//        }

		//Generating the msg entered on the terminal
		char msg[MSGLEN] = "";
		for (int i=1;i<count;i++){
			strcat(msg, cmd[i]);
			if(i != count-1) strcat(msg, " ");
		}

		//Generating the command entered on the terminal
		char buf[BUFLEN];
		strcpy(buf, cmd[0]);
		strcat(buf, " ");
		strcat(buf, msg);
		send(clientsockfd, buf, BUFLEN, 0);   //send the command to the server
		// rcv not written, also if rcv returns fail not handled  //CHECK
		cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);		
		cse4589_print_and_log("[%s:END]\n", cmd[0]);
		
	}else if(strcmp(cmd[0], "BLOCK") == 0){ //CHECKED - Has some part to be handled on the server side
		if (isClient != 1 || !loggedin || !is_valid_IP(cmd[1]) || count != 2 || !in_Cur_LogClients(cmd[1]) || alreadyBlocked(cmd[1], clientsockfd)) { 
			//on failure
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
			return;
		}

		//Generating the command entered on the terminal
		char buf[BUFLEN];
		strcpy(buf, cmd[0]);
		strcat(buf, " ");
		strcat(buf, cmd[1]);

		send(clientsockfd, buf, BUFLEN, 0);  //send the command to the server

		char res[10];
		recv(clientsockfd, res, 10, 0);  //server response
		if(strcmp(res, "FAIL") == 0){
			//on failure
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
		}else{
			//on success
			cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
		}

	}else if(strcmp(cmd[0], "UNBLOCK") == 0){ //CHECKED - Has some part to be handled on the server side
		if(isClient != 1 || !loggedin || !is_valid_IP(cmd[1]) || count != 2 || !in_Cur_LogClients(cmd[1]) || !alreadyBlocked(cmd[1], clientsockfd)){ /
			//on failure
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
			return;
		}

		//Generating the command entered on the terminal
		char buf[BUFLEN];
		strcpy(buf, cmd[0]);
		strcat(buf, " ");
		strcat(buf, cmd[1]);

		send(clientsockfd, buf, BUFLEN, 0); //send the command to the server

		char res[10];
		recv(clientsockfd, res, 10, 0); //server response
		if(strcmp(res, "FAIL") == 0){  //CHECK can remove fail
			//on failure
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
		}else{
			//on success
			cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
		}

	}else if(strcmp(cmd[0], "LOGOUT") == 0){//CHECKED - Has some part to be handled on the server side
		if(isClient && !loggedin){
			//on failure
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);		
			cse4589_print_and_log("[%s:END]\n", cmd[0]);		
			return;
		}
		char buf[BUFLEN] = "LOGOUT";
		send(clientsockfd, buf, BUFLEN, 0); //send the command to the server
		loggedin = 0;         //logged-out
		close(clientsockfd);  //close the socket
		FD_CLR(clientsockfd, &master);  //clear closed socket from master list
		cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);		
		cse4589_print_and_log("[%s:END]\n", cmd[0]);
		// server response not present, also error msg not handled 
	// git push exit event
	}/*else if(strcmp(cmd[0], "STATISTICS") == 0){
		if(role != 1){
			//fail
		cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);
		
		cse4589_print_and_log("[%s:END]\n", cmd[0]);
		
		return;
		}
		cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);
		
		for(int i=0;i<connIndex;i++){
			char tmp[20];
			if(connections[i].status == logged_in){
				strcpy(tmp, "logged-in");
			}else{
				strcpy(tmp, "logged-out");
			}

			cse4589_print_and_log("%-5d%-35s%-8d%-8d%-8s\n", i+1, connections[i].hostname, connections[i].msg_sent, connections[i].msg_received, tmp);
			
			//cse4589
		}
		cse4589_print_and_log("[%s:END]\n", cmd[0]);
		

	}*/
	
	/*CHECKED STATISTICS COMMAND BY ALOK TRIPATHY*/
	else if (strcmp(cmd[0],"STATISTICS") == 0)
	{
		if (role == 1)
		int temp[100]
		{
			cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);
			int i = 0
			while(i < connIndex)
			{
				char tmp[20];

				if(connections[i].status == logged_in)
					strcpy(tmp, "logged-in");
				else
					strcpy(tmp, "logged-out");

				cse4589_print_and_log("%-5d%-35s%-8d%-8d%-8s\n", i+1, connections[i].hostname, connections[i].msg_sent, connections[i].msg_received, tmp);
				
				i++;
			}
			cse4589_print_and_log("[%s:END]\n", cmd[0]);

		}

		else
		{
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);
			cse4589_print_and_log("[%s:END]\n", cmd[0]);
			return;
		}
	}

	/*CHECKED BLOCKED COMMAND BY ALOK TRIPATHY*/
	else if(strcmp(cmd[0], "BLOCKED") == 0)
	{
         if(role != 1 || count != 2 || !isValidAddr(cmd[1], "8888"))
		 {
             //fail
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);
			fflush(stdout);
		  	cse4589_print_and_log("[%s:END]\n", cmd[0]);
			fflush(stdout);
            return;
         }
         int flag = 0;
         for(int i=0;i<connIndex;i++)
		 {
             if(strcmp(connections[i].remote_addr, cmd[1]) == 0)
			 {
                 flag = 1;
				 cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);
				 fflush(stdout);
                 for (int j=0; j<connections[i].blockindex; j++) 
				 {
                     //cse4589
                     cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", j+1, connections[i].blockedIPs[j]->hostname, connections[i].blockedIPs[j]->remote_addr, connections[i].blockedIPs[j]->portNum);
					 fflush(stdout);
                 }
                 break;
             }
         }

         if(flag == 0){
             //fail
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);
			fflush(stdout);
		  	cse4589_print_and_log("[%s:END]\n", cmd[0]);
			fflush(stdout);
            return;
         }else{
		  	cse4589_print_and_log("[%s:END]\n", cmd[0]);
			fflush(stdout);
		 }
     }

 }




/*
* Response to client incoming msges
*/
void response(char **arguments, int caller){  //CHECK caller - sockfd of the current client
	if(strcmp(arguments[0], "SEND") == 0){

		char msg[BUFLEN] = "";
		char senderaddr[INET_ADDRSTRLEN];
		int sender;
		for(sender=0;sender<connIndex;sender++){
			if(connections[sender].connsockfd == caller){  //identifying sender
				strcat(msg, connections[sender].remote_addr);
				strcat(msg, " ");
				strcat(msg, arguments[2]); //count-1
				strcat(msg, " ");

				strcpy(senderaddr, connections[sender].remote_addr); //fetch sender ipaddr
				break;
			}
		}

		int flag = 0;// check if the target already exited   //CHECK can be named "present"
		for(int i=0;i<connIndex;i++){
			if(strcmp(arguments[1], connections[i].remote_addr) == 0){
				flag = 1;  //indicates target has not exited
				if(isBlocked(caller, arguments[1])){   //checks if the target has blocked the sender or not
					send(caller, "BLOCKED", 7, 0);     //msg not sent to the receiver, but the sender is unware of this
					return;
				}

				// target is logged-in the server
				if(connections[i].status == logged_in){  
					send(connections[i].connsockfd, msg, BUFLEN, 0);
					connections[i].msg_received++;

					//trigger RELAYED event at the server
					cse4589_print_and_log("[%s:SUCCESS]\n" , "RELAYED");					
					cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", connections[sender].remote_addr, connections[i].remote_addr, arguments[2]);					
					cse4589_print_and_log("[%s:END]\n", "RELAYED");
					
				// target is logged-out, but not exited the server, buffer the message for the target
				}else{
					strcat(bufferedmsg, connections[i].remote_addr);
					strcat(bufferedmsg, "---");
					strcat(bufferedmsg, senderaddr);
					strcat(bufferedmsg, "---");
					strcat(bufferedmsg, arguments[2]);
					strcat(bufferedmsg, "---");
					connections[i].msg_received++;
				}
				break;
			}
		}

		if(flag==0){ //if the target is exited
			send(caller, "FAIL", 4, 0);  
		}
		else{ // if message is sent to the target
			send(caller, "SUCCESS", 7, 0);  //notify the sender
			connections[sender].msg_sent++;
		}

	}else if(strcmp(arguments[0], "REFRESH") == 0){
		char list[BUFLEN] = "";
		packClientInfo(list);
		send(caller, list, BUFLEN, 0);

	}else if(strcmp(arguments[0], "BROADCAST") == 0){

		char sender[INET_ADDRSTRLEN];
		char msg[BUFLEN];
		for(int i=0;i<connIndex;i++){
			if(connections[i].connsockfd == caller){
				connections[i].msg_sent++;
				strcpy(sender, connections[i].remote_addr);  // get sender ipaddr

				strcpy(msg, connections[i].remote_addr); 
				strcat(msg, " ");
				strcat(msg, arguments[1]);
				strcat(msg, " ");
			}
		}

		// server broadcast the msg to all linked clients. sends msg to logged-in clients and buffers for logged-out clients
		for (int i=0; i<connIndex; i++) {
			// handling self broadcast and clients that have blocked sender
			if(!isBlocked(caller, connections[i].remote_addr) && connections[i].connsockfd != caller){ 
				if(connections[i].status == logged_in){
					send(connections[i].connsockfd, msg, BUFLEN, 0);  //sending to logged-in target
					connections[i].msg_received++;
					//trigger RELAYED event
					cse4589_print_and_log("[%s:SUCCESS]\n" , "RELAYED");					
					cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", sender, "255.255.255.255", msg);					
					cse4589_print_and_log("[%s:END]\n", "RELAYED");
					
				}else{
//                    strcat(bufferedmsg, "255.255.255.255"); mark
					strcat(bufferedmsg, connections[i].remote_addr); //target ipaddr
					strcat(bufferedmsg, "---");
					strcat(bufferedmsg, sender);     //sender ipaddr
					strcat(bufferedmsg, "---");
					strcat(bufferedmsg, arguments[1]);  //msg body
					strcat(bufferedmsg, "---");
					connections[i].msg_received++;
				}
			}
		}
	}else if(strcmp(arguments[0], "BLOCK") == 0){
		int i = 0; int b = 0;
		for(i =0; i<connIndex; i++){
			if(connections[i].connsockfd == caller) break;  // connections[i]  -> client for which connections[b] is blocked
		}
		
		for(b =0; b<connIndex; b++){
			if(strcmp(connections[b].remote_addr, arguments[1] == 0) break;      // connections[b]  -> client to be blocked
		}

		connections[i].blockedIPs[connections[i].blockindex++] = &connections[b];  //adding blocked client info to curr clients blockedIP data structure
		
		//Sorting the block list as per increasing port number
		if(connections[i].blockindex > 1){
			for(int k=0;i<connections[i].blockindex-1;k++){
				for (int j=k+1; j<connections[i].blockindex; j++) {
					if(connections[i].blockedIPs[k]->portNum > connections[i].blockedIPs[j]->portNum){
						struct connection *tmp = connections[i].blockedIPs[k];
						connections[i].blockedIPs[k] = connections[i].blockedIPs[j];
						connections[i].blockedIPs[j] = tmp;
					}
				}
			}
		}
		send(caller, "SUCCESS", 7, 0);
		
	}else if(strcmp(arguments[0], "UNBLOCK") == 0){
		int i = 0;
		for(i = 0; i<connIndex;i++){
			if(connections[i].connsockfd == caller) break;
		}

		if(connections[i].blockindex == 0){
			send(caller, "FAIL", 4, 0);
			return;
		}

		int flag = 0;
		for(int m=0;i<connections[i].blockindex;m++){
			if(strcmp(connections[i].blockedIPs[i]->remote_addr, arguments[1]) == 0){
				if(m == (connections[i].blockindex -1)){    //Check if the last blocked client is unblocked
					connections[i].blockindex--;
					flag = 1;
					break;
				}
				// shift the blocked clients upwards if any of the middle clients is unblocked
				for(int j=m+1;j<connections[i].blockindex;j++){ 
					connections[i].blockedIPs[j-1] = connections[i].blockedIPs[j];
				}
				flag = 1;
				connections[i].blockindex--;
				break;
			}
		}
		if(flag == 0){
			send(caller, "FAIL", 4, 0);
			return;
		}
		send(caller, "SUCCESS", 7, 0);

	}
	
	/*Checked by Alok Tripathy.*/
	else if(strcmp("EXIT", arguments[0]) == 0)
	{
		int target = 0;
		while(target<connIndex)
		{
			if(connections[target].connsockfd == caller)
			{
				close(connections[target].connsockfd);
				FD_CLR(connections[target].connsockfd, &master);
				if(target == 3){  //last of the all 4 logged-in clients
					connIndex--;
					break;
				}
				for(int j=target+1;j<connIndex;j++){  //removes the details of the exited client
					connections[j-1] = connections[j];
					j++;
				}
				connIndex--;
				break;
			}
			
			target++;
		}
	}

	/* Checked by Alok Tripathy*/
	else if(strcmp("LOGOUT",arguments[0]) == 0)
	{
		int i = 0;
		while(i<connIndex)
		{
			if(connections[i].connsockfd == caller)
			{
				close(connections[i].connsockfd);
				FD_CLR(connections[i].connsockfd, &master);
				connections[i].status = logged_out;
				break;
			}
			i++;
		}
	}
}

/*
*  select for cmd and connecting.
*/

// Check the localsockfd and the clientsockfd conflict ##############################//

void start(void){
	char *argm[5];  //variable to store different parts of the stdin

	// Initializes file descripter to have zero bits
	FD_ZERO(&master);
	FD_ZERO(&read_fds);

	FD_SET(STD_IN, &master);  // Set STDIN to master_list
	FD_SET(localsockfd, &master);  // Set localsockfd to master_list
	maxfd = localsockfd;

	while (1) {
		read_fds = master;
		// select() ->  indicates which of the specified file descriptors is ready for reading, blocks if none is ready
		if(select(maxfd+1, &read_fds, NULL, NULL, NULL) == -1){
			perror("select() error"); 
			exit(-1);
		}

		// fetching the available socket 
		for(int i=0 ;i < maxfd+1; i++){
			if(FD_ISSET(i, &read_fds)){
				// This section of code handles the terminal input and fetches the command and input arguments
				if(i == STD_IN){
					char *cmd = (char *)malloc(sizeof(char)*CMD_SIZE);
					memset(cmd, '\0', CMD_SIZE);
					fgets(cmd, CMD_SIZE-1, stdin);
					for(int j =0; j<CMD_SIZE; j++){
						if(cmd[j] == '\n'){
							cmd[j] = '\0';
							break;
						}
					}

					int args_num = 0;
					char *tmp = strtok(cmd, " ");
					while(tmp != NULL){
						argm[args_num++] = tmp;   //argm stores all the parts of input provided through terminal
						tmp = strtok(NULL, " ");
					}

					shellCmd(argm, args_num);   //user defined function that implements set of events

				}else if(i == localsockfd && isClient == 0){ //In server mode
					// process new connections, use a data structure to store info
					struct sockaddr_storage remoteaddr;
					socklen_t len = sizeof(remoteaddr);
					int newfd = accept(localsockfd, (struct sockaddr *)&remoteaddr, &len);
					if(newfd == -1){ 
						//flag = -1; //check
						continue;  //check for another available socket
					}
					FD_SET(newfd, &master); // Set newfd to master_list
					maxfd = maxfd > newfd? maxfd: newfd;   // sets new max value

					/*##### CAN BE CLUBBED TO ONE FUNCTION - START #####*/

					char clientPort[PORTSTRLEN];   
					// bug: different length between client and server   //check 
					recv(newfd, clientPort, PORTSTRLEN, 0);
					char tmp[INET_ADDRSTRLEN];   //buffer with size INET_ADDRSTRLEN
					inet_ntop(AF_INET, &(((struct sockaddr_in *)&remoteaddr)->sin_addr), tmp, INET_ADDRSTRLEN);

					struct hostent *he;
					struct in_addr ipv4addr; 
					inet_pton(AF_INET, tmp, &ipv4addr);
					he = gethostbyaddr(&ipv4addr, sizeof(struct in_addr), AF_INET);  //returns data in hostent structure

					int exist = 0;
					for(int i=0;i<connIndex;i++){
						if(strcmp(connections[i].remote_addr, tmp) == 0){ //checks if any of the conections have same addr
							exist = 1;
							connections[i].status = logged_in; //updates status for the host
							break;
						}
					}
					//if not match found, maintain a new connection record
					if(!exist){  
						struct connection newConnection;
						newConnection.connsockfd = newfd;
						strcpy(newConnection.remote_addr, tmp);
						//newConnection.portNum = ((struct sockaddr_in *)&remoteaddr)->sin_port;  //remove
						newConnection.portNum = strToNum(clientPort);
						strcpy(newConnection.hostname, he->h_name);
						newConnection.msg_sent = 0;
						newConnection.msg_received = 0;
						newConnection.status = logged_in;
						newConnection.blockindex = 0;
						connections[connIndex++] = newConnection;  //append to our previous connection set
					}
					// Sorting the connection array in increasing order of the port number
					if(connIndex > 1){
						for(int m = 0; m< connIndex-1; m++){
							for(int fast = m+1; fast<connIndex; fast++){
								if(connections[m].portNum > connections[fast].portNum){
									struct connection tmp = connections[m];
									connections[m] = connections[fast];
									connections[fast] = tmp;
								}
							}
						}
					}
					/*##### CAN BE CLUBBED TO ONE FUNCTION - END #####*/

					//1. sents packed list of current logged-in clients to the newly connected client
					char list[BUFLEN] = "";
					packClientInfo(list);
					send(newfd, list, BUFLEN, 0);  


					//2. Prepare buffered msg for that client
					int count = 0;
					char *bufmsg[BUFLEN];
					char *p;
					p = strtok(bufferedmsg, "---");
					while (p!=NULL) {
						bufmsg[count++] = p;
						p = strtok(NULL, "---");
					}

					char newBufferedmsg[BUFLEN]="";
					char sendingmsg[BUFLEN]="";

					int flag = 0;   //Flag for Broadcast msg
					for (int i=0; i<count; ) {
						if (strcmp(tmp, bufmsg[i]) == 0) {  //matching the IP address in the msg with the cient
							if(flag == 0){
								strcat(sendingmsg, "BROADCAST,");
								strcat(sendingmsg, "---");
								flag = 1;
							}
							strcat(sendingmsg, bufmsg[i+1]);  //generating buffered msg for the client
							strcat(sendingmsg, "---");
							strcat(sendingmsg, bufmsg[i+2]);
							strcat(sendingmsg, "---");
							cse4589_print_and_log("[%s:SUCCESS]\n", "RELAYED");							
							cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", bufmsg[i+1], bufmsg[i], bufmsg[i+2]);
							cse4589_print_and_log("[%s:END]\n", "RELAYED");
							
							i+=3; //three terms getting used in one message send
						} else if(strcmp(bufmsg[i], "255.255.255.255") == 0){  //means its broadcasted mesage
							if(flag == 0){
								strcat(sendingmsg, "BROADCAST,");
								strcat(sendingmsg, "---");
								flag = 1;
							}
							strcat(newBufferedmsg, "255.255.255.255"); //maintain copy for other clients in the broadcast network
							strcat(newBufferedmsg, "---");
							strcat(newBufferedmsg, bufmsg[i+1]);
							strcat(newBufferedmsg, "---");
							strcat(newBufferedmsg, bufmsg[i+2]);
							strcat(newBufferedmsg, "---");

							strcat(sendingmsg, bufmsg[i+1]);  //generating buffered msg for the client
							strcat(sendingmsg, "---");
							strcat(sendingmsg, bufmsg[i+2]);
							strcat(sendingmsg, "---");
							cse4589_print_and_log("[%s:SUCCESS]\n", "RELAYED");							
							cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", bufmsg[i+1], bufmsg[i], bufmsg[i+2]);		
							cse4589_print_and_log("[%s:END]\n", "RELAYED");
							
							i+=3;
						} else{                                         // buffer holds msgs of other clients
							strcat(newBufferedmsg, bufmsg[i++]);
							strcat(newBufferedmsg, "---");
							strcat(newBufferedmsg, bufmsg[i++]);
							strcat(newBufferedmsg, "---");
							strcat(newBufferedmsg, bufmsg[i++]);
							strcat(newBufferedmsg, "---");
						}
					}
					strcpy(bufferedmsg, newBufferedmsg);  // copy back to original buffer
			
					send(newfd, sendingmsg, BUFLEN, 0);  //send msg to client

				}else if(i == clientsockfd && isClient == 1){ //In client mode
					char buf[BUFLEN];
					int nbytes = recv(i, buf, sizeof buf, 0);  					
					char flag[10]="";

					if(nbytes > 1){   //Some data is received
						strncpy(flag, buf, 10);  // copies only upto 10 characters
						}

					if(strcmp(flag, "BROADCAST,") == 0){
					char *tmp;
					int count = 0;
					char *msgset[BUFLEN];
					tmp = strtok(buf, "---");
					while (tmp != NULL) {
						msgset[count++] = tmp;
						tmp = strtok(NULL, "---");
					}
				
					//prints and logs the msgs on the client side
					for(int i=1;i<count;){ // i=0, represents the command sent 
						cse4589_print_and_log("[%s:SUCCESS]\n", "RECEIVED");						
						cse4589_print_and_log("msg from:%s\n[msg]:%s\n", msgset[i], msgset[i+1]);						
						cse4589_print_and_log("[%s:END]\n", "RECEIVED");												
						i+=2;
					}


					}else{  
							char *tmp;
							int count = 0;
							char *msgset[BUFLEN];
							tmp = strtok(buf, " ");
							while (tmp != NULL) {
								msgset[count++] = tmp;
								tmp = strtok(NULL, " ");
							}

							char recvmsg[MSGLEN] = "";
							for(int n = 1; n< count; n++){
							strcat(recvmsg, msgset[n]);
							if(n<count-1) strcat(recvmsg, " ");
							}

							cse4589_print_and_log("[%s:SUCCESS]\n", "RECEIVED");							
							cse4589_print_and_log("msg from:%s\n[msg]:%s\n", msgset[0], recvmsg);							
							cse4589_print_and_log("[%s:END]\n", "RECEIVED");
							
							}
					// triger event cse4589
					// recv from server to receive msg from others
				}else{
					char buf[BUFLEN];
					ssize_t nbytes = recv(i, buf, sizeof buf, 0);
					buf[nbytes] = '\0';

					int count = 0;
					char *p;
					char *arguments[BUFLEN];
					p = strtok(buf, " ");
					while (p != NULL) {
						arguments[count++] = p;
						p = strtok(NULL, " ");
					}

					char msg[MSGLEN] = "";

					if(strcmp(arguments[0], "SEND") == 0){
						for(int i=2; i<count; i++){
						strcat(msg, arguments[i]);
						if(i < count-1) strcat(msg, " ");
						}
						count = 3;
						arguments[count-1] = msg;
					}

					if(strcmp(arguments[0], "BROADCAST") == 0){
					for(int i=1; i<count; i++){
						strcat(msg, arguments[i]);
						if(i < count-1) strcat(msg, " ");
						}
						count = 2;
						arguments[count-1] = msg;
					}

					if(strcmp(arguments[0], "BLOCK") == 0){
					for(int i=1; i<count; i++){
						strcat(msg, arguments[i]);
						if(i < count-1) strcat(msg, " ");
						}
						count = 2;
						arguments[count-1] = msg;
					}

					if(strcmp(arguments[0], "UNBLOCK") == 0){
					for(int i=1; i<count; i++){
						strcat(msg, arguments[i]);
						if(i < count-1) strcat(msg, " ");
						}
						count = 2;
						arguments[count-1] = msg;
					}
					//debug
					//printf("%s\n%s\n", msg, arguments[count]);

				// for(int l = 0; l < count; l++){
				//	printf("%s--- ", arguments[l]);
					//}
					//printf("\n");

				response(arguments, clientsockfd); //CHECK replaced i with clientsockfd
					// recv from connected socket, also need to consider argument,send, refresh or block.  //CHECK

				}
			}
		}
	}
}

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
	int sock_fd = 0;
	//int fdsocket = 0;


	/*Start Here*/
	//Initiaties the further steps only when the segment is passed
	if (argc == 3)
	{
		// This segment creates socket for the server and binds it to a port and puts it in listen mode
		if (strcmp(argv[1], "s") == 0)
		{
			// TODO - ALOK
			isClient = 0;
			strcpy(listenerPort, argv[2]);
			localsockfd = bind_socket(listenerPort);
			if(listen(localsockfd, BACKLOG) == -1)
			{
				exit(-1);
			}
			start();
		}


		// This segment creates socket for the client and binds it to a port and puts it in connect mode
		else if (strcmp(argv[1], "c") == 0)
		{
			isClient = 1;
			strcpy(listenerPort, argv[2]);
			localsockfd = bind_socket(listenerPort);
			// prep(argv[2]);
			start();
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


