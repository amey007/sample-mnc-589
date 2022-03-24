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

int socketfd;  //localsockfd
int clientsockfd;
int isServer = 0; // denote server - 1, or client - 0
int hostIndex = 0;
int logedin = 0; // a flag to indicate log in, avoid multible log in
char lis_port[PORTSTRLEN];

struct host {
	char hostname[HOSTNAMESTRLEN];
	char ip_addr[INET_ADDRSTRLEN]; //remote_addr
	int portNum;
	int msg_received;
	int msg_sent;
	int status;
	int blockindex;
	struct host *blockedIPs[3];
	int hostsockfd; //connsockfd
};

struct host hosts[4];
char bufferedmsg[BUFLEN] = "";

fd_set master_list, watch_list;
int maxfd;


/*int get_IP(char *res){
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
}*/

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

int is_valid_port(const char *input) {
	int i = 0;
	if(input[i] == '-') { return 0; }
	for(; input[i] != '\0'; i++) {
		if(!isdigit(input[i])) return 0;
	}
	return 1;
}

int is_valid_IP(const char *ip) { 	
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

/*
* Preparation, create socket and listen for connection.
* Success return 0, otherwise -1
*/
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
		if((socketfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
			continue;
		}

		if(bind(socketfd, p->ai_addr, p->ai_addrlen) == -1){
			close(socketfd);
			continue;
		}
		break;
	}

	if(p == NULL) return -1;
	freeaddrinfo(servinfo);

	if(listen(socketfd, BACKLOG) == -1){
		return -1;
	}

	return 0;
}


int strToInt(const char* s){
	int ret = 0;
	for (int i=0;i<strlen(s);i++){
		int t = s[i]-'0';
		if  (t<0 || t >9) return -1;
		ret = ret*10+t;
	}
	return ret;
}


/*
* Check if given addr and #port is valid
*/
//remove this afterwards
/*int isValidAddr(char *addr, char *port){
	//debug
	//addr[strlen(addr)] = '\0';
	//port[strlen(port)] = '\0';
	int ret = 1;
	for(int i=0; i<CMD_LEN;i++){
		if(*(addr+i) == '\0') break;
		if(*(addr+i) == '.') continue;
		int t = *(addr+i) - '0';
		if(t<0 || t>9) {
			ret = 0;
			break;
		}
	}

	for(int i=0; i<CMD_LEN;i++){
		if(*(port+i) == '\0') break;
		int t = *(port+i) - '0';
		if(t<0 || t>9) {
			ret = 0;
			break;
		}
	}
	return ret;
}*/

/*
* Pack & unpack the list info to send,
* argm list shoulb be empty string "",
* res store in an struct conns array
*/
//remove this afterwards
/*void packList(char *list){
	for (int i=0; i<hostIndex; i++) {
		if(hosts[i].status == login){
			char tmp[PORTSTRLEN];
			char status[5];
			// int to string
			sprintf(tmp, "%d", hosts[i].portNum);
			sprintf(status, "%d", hosts[i].status);

			strcat(list, hosts[i].hostname);
			strcat(list, "---");
			strcat(list, hosts[i].ip_addr);
			strcat(list, "---");
			strcat(list, tmp);
			strcat(list, "---");
			strcat(list, status);
			strcat(list, "---");
		}
	}
}*/

void packClientInfo(char *list){
	for (int i=0; i<hostIndex; i++) {
		if(hosts[i].status == login){
			char tmp[PORTSTRLEN];
			char status[5];
			// int to string
			sprintf(tmp, "%d", hosts[i].portNum);
			sprintf(status, "%d", hosts[i].status);

			strcat(list, hosts[i].hostname);
			strcat(list, "---");
			strcat(list, hosts[i].ip_addr);
			strcat(list, "---");
			strcat(list, tmp);
			strcat(list, "---");
			strcat(list, status);
			strcat(list, "---");
		}
	}
}


void unpack_store(char *list){
	char *parts[20];
	int count = 0;
	char *p;
	p = strtok(list, "---");
	while (p != NULL) {
		parts[count++] = p;
		p = strtok(NULL, "---");
	}

	if (hostIndex != 0) hostIndex = 0;
	for(int i=0;i<count;){
		strcpy(hosts[hostIndex].hostname, parts[i++]);
		strcpy(hosts[hostIndex].ip_addr, parts[i++]);
		int tmp = strToInt(parts[i++]);
		hosts[hostIndex].portNum = tmp;
		tmp = strToInt(parts[i++]);
		hosts[hostIndex++].status = tmp;
	}

}

//remove this afterwards
/*void unpackList(char *list){
	char *parts[20];
	int count = 0;
	char *p;
	p = strtok(list, "---");
	while (p != NULL) {
		parts[count++] = p;
		p = strtok(NULL, "---");
	}

	if (hostIndex != 0) hostIndex = 0;
	for(int i=0;i<count;){
		strcpy(hosts[hostIndex].hostname, parts[i++]);
		strcpy(hosts[hostIndex].ip_addr, parts[i++]);
		int tmp = strToInt(parts[i++]);
		hosts[hostIndex].portNum = tmp;
		tmp = strToInt(parts[i++]);
		hosts[hostIndex++].status = tmp;
	}

}*/

/*
* Check if certain sender is blocked by receiver
* return 0 if not blocked
*/

int isBlocked(int sender, char *receiver){
	int ret = 0;

	char sender_ip[INET_ADDRSTRLEN] = "";
	for(int i=0;i<hostIndex;i++){
		if(hosts[i].hostsockfd == sender){
			strcpy(sender_ip, hosts[i].ip_addr);
			break;
		}
	}
	for(int i =0; i<hostIndex; i++){
		if(strcmp(hosts[i].ip_addr, receiver) == 0){
			for(int j=0; j <hosts[i].blockindex;j++){
				if(strcmp(hosts[i].blockedIPs[j]->ip_addr, sender_ip) == 0){
					ret = 1;
					break;
				}
			}
			break;
		}
	}

	return ret;
}


void shellCmds(char **cmd, int count){

	if (strcmp(cmd[0], "AUTHOR") == 0) 
	{
		cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);
		char your_ubit_name[9] = "ameynare";		
		cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", your_ubit_name);		
		cse4589_print_and_log("[%s:END]\n", cmd[0]);		
	}
	else if(strcmp(cmd[0], "IP") == 0)
	{
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
		if (isServer && !logedin)
		{
			// on failure
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
			return;
		}else
		{
			int count = 1;
			cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);
			//loop to print the client details from the stored struct data structure		
			for(int i=0;i<hostIndex;i++){
				if(hosts[i].status == login){
					cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", count++, hosts[i].hostname, hosts[i].ip_addr, hosts[i].portNum);				
				}
			}
			cse4589_print_and_log("[%s:END]\n", cmd[0]);
		}
	}
	else if(strcmp(cmd[0], "LOGIN") == 0){ 
		// printf("Entered LOGIN loop");
		// printf("%d\n",is_valid_IP(cmd[1]));
		// printf("%d\n",is_valid_IP(cmd[1]));
		// printf("%d\n",loggedin);
		// printf("%d\n",isClient);
		// printf("%d\n",count);
		if(isServer || count != 3 || !is_valid_IP(cmd[1]) || !is_valid_port(cmd[2]) || logedin){
			// only when fails to meet the required conditions
			printf("Error in exception catch");	
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);					
			return;
		}

		int server_port = atoi(cmd[2]); 
		//int socketfd; 
		struct sockaddr_in server_addr, client_addr;

		clientsockfd = socket(AF_INET, SOCK_STREAM, 0); 
		if (clientsockfd < 0) { 
			perror("socket() failed\n"); 
		}
		// bzero(&client_addr, sizeof(client_addr)); 
		// client_addr.sin_family = AF_INET;
		// client_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
		// client_addr.sin_port = htons(strToNum(listenerPort)); 
		// if (bind(clientsockfd, (struct sockaddr *) &client_addr, sizeof(struct sockaddr_in)) != 0) { 
		// 	perror("failed to bind port to client"); 
		// }
		
		bzero(&server_addr, sizeof(server_addr));
		server_addr.sin_family = AF_INET;
		inet_pton(AF_INET, cmd[1], &server_addr.sin_addr);
		server_addr.sin_port = htons(server_port);

		if(connect(clientsockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);
			cse4589_print_and_log("[%s:END]\n", cmd[0]);
			return; 
		}
				
		printf("Socket conencted");
		send(clientsockfd, lis_port, sizeof lis_port, 0); //sends port number to the server to fetch its buffered messages and list of logged-in clients 

		printf("Send to Server");

		// Stores the data provided by server on successful registration
		char clientList[BUFLEN];
		recv(clientsockfd, clientList, BUFLEN, 0);  //receives the list of logged-in clients from the server
		printf("Received from Server");
		unpack_store(clientList);                 

		char bufmsgList[BUFLEN];
		recv(clientsockfd, bufmsgList, BUFLEN, 0);  //receives the list of buffered msgs from the server
		char *msgbuf[BUFLEN];
		int count = 0;
		char *q = strtok(bufmsgList, "---");
		while (q!=NULL) {
			msgbuf[count++] = q;
			q = strtok(NULL, "---");
		}
		for(int i=1;i<count; ){    //CHECK HERE why i=1, not 0
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
	else if(strcmp(cmd[0], "REFRESH") == 0){
		if(isServer != 0 || !logedin){
			//fail
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
	//pending to correct
	else if(strcmp(cmd[0], "SEND") == 0){
		if(isServer != 0 || !logedin || !isValidAddr(cmd[1], "8888")){
			//fail
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
			return;
		}

		// check if recvier is in local list
		int flag = 0;
		for (int i=0; i<hostIndex; i++) {
			if (strcmp(cmd[1], hosts[i].ip_addr) == 0) {
				flag = 1;
				break;
			}
		}
		if(flag == 0) {
			//fail
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);
			
			return;
		}

		char msg[MSGLEN] = "";
		for (int i=2;i<count;i++){
			strcat(msg, cmd[i]);
			if(i != count-1) strcat(msg, " ");
		}

		char buf[BUFLEN] = "";
		strcat(buf, cmd[0]);
		strcat(buf, " ");
		strcat(buf, cmd[1]);
		strcat(buf, " ");
		strcat(buf, msg);
		send(clientsockfd, buf, sizeof(buf), 0);// sizeof buf  also works?

		char res[10];
		recv(clientsockfd, res, 10, 0);
		//debug
	//  printf("--%s--\n", res);
		if (strcmp(res, "FAIL") == 0) {
			//fail
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);
			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);
			
		}else{
			//success
			cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);
			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);
			
		}

	}
	else if (strcmp(cmd[0], "BROADCAST") == 0){
		if (isServer != 0 || !logedin) {
			//fail
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
			return;
		}

		char msgbody[MSGLEN] = "";
		for (int i=1;i<count;i++){
			strcat(msgbody, cmd[i]);
			if(i != count-1) strcat(msgbody, " ");
		}

		char tercmd[BUFLEN];
		strcpy(tercmd, cmd[0]);
		strcat(tercmd, " ");
		strcat(tercmd, msgbody);
		send(clientsockfd, tercmd, BUFLEN, 0);
		cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);		
		cse4589_print_and_log("[%s:END]\n", cmd[0]);
		
	}
	else if(strcmp(cmd[0], "BLOCK") == 0){
		if (isServer != 0 || !logedin || !is_valid_IP(cmd[1]) || count != 2) {
			//fail
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
			return;
		}

		// Checking for IP address match in local list
		int flag = 0;
		for(int i=0;i<hostIndex;i++){
			if(strcmp(hosts[i].ip_addr, cmd[1]) == 0){
				flag = 1;  //present in local list
				break;
			}
		}

		if(flag == 0){
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

		char res[10];  //result received from server
		recv(clientsockfd, res, 10, 0);
		if(strcmp(res, "FAIL") == 0){
			//fail
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);
			
		}else{
			//success
			cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);
			
		}

	}else if(strcmp(cmd[0], "UNBLOCK") == 0){
		if(isServer != 0 || !logedin || !is_valid_IP(cmd[1]) || count != 2){
			//fail
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
			return;
		}

		// Checking for IP address match in local list
		int flag = 0;
		for(int i=0;i<hostIndex;i++){
			if(strcmp(hosts[i].ip_addr, cmd[1]) == 0){
				flag = 1;
				break;
			}
		}
		if(flag == 0){
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
		if(strcmp(res, "FAIL") == 0){
			//fail
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);
			
		}else{
			//success
			cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);			
			cse4589_print_and_log("[%s:END]\n", cmd[0]);			
		}

	}
	else if(strcmp(cmd[0], "EXIT") == 0){
		char buf[BUFLEN] = "EXIT";
		send(clientsockfd, buf, BUFLEN, 0);
		logedin = 0;
		close(clientsockfd);
		FD_CLR(clientsockfd, &master_list);
		cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);		
		cse4589_print_and_log("[%s:END]\n", cmd[0]);		
		exit(0);
	}
	else if(strcmp(cmd[0], "LOGOUT") == 0){
		if(!logedin){
			//fail
		cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);		
		cse4589_print_and_log("[%s:END]\n", cmd[0]);		
		return;
		}

		char buf[BUFLEN] = "LOGOUT";
		send(clientsockfd, buf, BUFLEN, 0); 
		logedin = 0;
		close(clientsockfd);
		FD_CLR(clientsockfd, &master_list);
		cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);		
		cse4589_print_and_log("[%s:END]\n", cmd[0]);		

	}
	else if(strcmp(cmd[0], "STATISTICS") == 0){
		if(isServer != 1){
		//fail
		cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);		
		cse4589_print_and_log("[%s:END]\n", cmd[0]);		
		return;
		}
		cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);

		for(int i=0;i<hostIndex;i++){
			char tmp[20];
			if(hosts[i].status == login){
				strcpy(tmp, "logged-in");
			}else{
				strcpy(tmp, "logged-out");
			}

			cse4589_print_and_log("%-5d%-35s%-8d%-8d%-8s\n", i+1, hosts[i].hostname, hosts[i].msg_sent, hosts[i].msg_received, tmp);
			
		}
		cse4589_print_and_log("[%s:END]\n", cmd[0]);
	}
	else if(strcmp(cmd[0], "BLOCKED") == 0){
		if(isServer != 1 || count != 2 || !is_valid_IP(cmd[1])){
			//fail
		cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);		
		cse4589_print_and_log("[%s:END]\n", cmd[0]);		
		return;
		}

		int flag = 0, i= 0;
		while(i<hostIndex){
			if(strcmp(hosts[i].ip_addr, cmd[1]) == 0){ // fetching the clients struct host
				flag = 1;
				cse4589_print_and_log("[%s:SUCCESS]\n", cmd[0]);
				
				for (int j=0; j<hosts[i].blockindex; j++) { //looping through the block clients struct in the host struct
					//cse4589
					cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", j+1, hosts[i].blockedIPs[j]->hostname, hosts[i].blockedIPs[j]->ip_addr, hosts[i].blockedIPs[j]->portNum);					
				}
				break;
			}
			i++;
		}

		if(flag == 0){
			//fail
			cse4589_print_and_log("[%s:ERROR]\n", cmd[0]);		
			cse4589_print_and_log("[%s:END]\n", cmd[0]);		
			return;
		}else{
			cse4589_print_and_log("[%s:END]\n", cmd[0]);
		
		}
	}
}

/*
* Response to client incoming msges
*/
void server_response(char **arguments, int count, int calling_client){  
	if(strcmp(arguments[0], "SEND") == 0){

		char msg[BUFLEN] = "";
		char sender_ip[INET_ADDRSTRLEN];
		int sender= 0;
		for(sender=0;sender<hostIndex;sender++){
			if(hosts[sender].hostsockfd == calling_client){
				strcat(msg, hosts[sender].ip_addr);
				strcat(msg, " ");
				strcat(msg, arguments[2]);
				strcat(msg, " ");

				strcpy(sender_ip, hosts[sender].ip_addr);
				break;
			}
		}

		int flag = 0; //indicates already exited
		for(int i=0;i<hostIndex;i++){
			if(strcmp(arguments[1], hosts[i].ip_addr) == 0){
				flag = 1;
				if(isBlocked(calling_client, arguments[1])){
					send(calling_client, "BLOCKED", 7, 0);
					return;
				}

				if(hosts[i].status == login){
					send(hosts[i].hostsockfd, msg, BUFLEN, 0);
					hosts[i].msg_received++;
					//triger event
					cse4589_print_and_log("[%s:SUCCESS]\n" , "RELAYED");					
					cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", hosts[sender].ip_addr, hosts[i].ip_addr, arguments[2]);					
					cse4589_print_and_log("[%s:END]\n", "RELAYED");
					

				}else{
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
		}
		if(flag==0){
			send(calling_client, "FAIL", 4, 0);
		}else{
			send(calling_client, "SUCCESS", 7, 0);
			hosts[sender].msg_sent++;
		}

	}
	else if(strcmp(arguments[0], "REFRESH") == 0){
		char clientList[BUFLEN] = "";
		packClientInfo(clientList);
		send(calling_client, clientList, BUFLEN, 0);
	}
	else if(strcmp(arguments[0], "BROADCAST") == 0){
		char sender_ip[INET_ADDRSTRLEN];
		char msg[BUFLEN];
		for(int i=0;i<hostIndex;i++){
			if(hosts[i].hostsockfd == calling_client){
				hosts[i].msg_sent++;
				strcpy(sender_ip, hosts[i].ip_addr);
				strcpy(msg, hosts[i].ip_addr);
				strcat(msg, " ");
				strcat(msg, arguments[1]);
				strcat(msg, " ");
			}
		}

		for (int i=0; i<hostIndex; i++) {
			if(!isBlocked(calling_client, hosts[i].ip_addr) && hosts[i].hostsockfd != calling_client){
				if(hosts[i].status == login){
					send(hosts[i].hostsockfd, msg, BUFLEN, 0);
					hosts[i].msg_received++;
					//triger event
					cse4589_print_and_log("[%s:SUCCESS]\n" , "RELAYED");					
					cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", sender_ip, "255.255.255.255", msg);					
					cse4589_print_and_log("[%s:END]\n", "RELAYED");
					
				}else{
					strcat(bufferedmsg, hosts[i].ip_addr);
					strcat(bufferedmsg, "---");
					strcat(bufferedmsg, sender_ip);
					strcat(bufferedmsg, "---");
					strcat(bufferedmsg, arguments[1]);
					strcat(bufferedmsg, "---");
					hosts[i].msg_received++;
				}
			}
		}
	}else if(strcmp(arguments[0], "BLOCK") == 0){

		int t;
		for(t=0;t<hostIndex;t++){
			if(hosts[t].hostsockfd == calling_client) break;
		}

		int found = 0;
		int b;
		for (b = 0; b< hostIndex; b++) {
			if(strcmp(hosts[b].ip_addr, arguments[1])== 0) {
				found = 1;
				break;
			}
		}

		if(found == 0){
			send(calling_client, "FAIL", 4, 0);
			return;
		}

		if (hosts[t].blockindex == 0) {
			//potential bug, if the b client already exited
			hosts[t].blockedIPs[hosts[t].blockindex++] = &hosts[b];
		}else{
			for(int i=0;i<hosts[t].blockindex; i++){
				if(strcmp(hosts[t].blockedIPs[i]->ip_addr, arguments[1]) == 0){
					send(calling_client, "FAIL", 4, 0);
					return;
				}
			}
			hosts[t].blockedIPs[hosts[t].blockindex++] = &hosts[b];

			//sort the block list
			if(hosts[t].blockindex > 1){
				for(int i=0;i<hosts[t].blockindex-1;i++){
					for (int j=i; j<hosts[t].blockindex; j++) {
						if(hosts[t].blockedIPs[i]->portNum > hosts[t].blockedIPs[j]->portNum){
							struct host *tmp = hosts[t].blockedIPs[i];
							hosts[t].blockedIPs[i] = hosts[t].blockedIPs[j];
							hosts[t].blockedIPs[j] = tmp;
						}
					}
				}
			}
		}
		send(calling_client, "SUCCESS", 7, 0);

	}else if(strcmp(arguments[0], "UNBLOCK") == 0){
		int t = 0;
		for(t = 0; t<hostIndex;t++){
			if(hosts[t].hostsockfd == calling_client) break;
		}

		if(hosts[t].blockindex == 0){
			send(calling_client, "FAIL", 4, 0);
			return;
		}

		int flag = 0;
		for(int i=0;i<hosts[t].blockindex;i++){
			if(strcmp(hosts[t].blockedIPs[i]->ip_addr, arguments[1]) == 0){
				if(i == 2){
					hosts[t].blockindex--;
					flag = 1;
					break;
				}
				for(int j=i+1;j<hosts[t].blockindex;j++){
					hosts[t].blockedIPs[j-1] = hosts[t].blockedIPs[j];
				}
				flag = 1;
				hosts[t].blockindex--;
				break;
			}
		}
		if(flag == 0){
			send(calling_client, "FAIL", 4, 0);
			return;
		}
		send(calling_client, "SUCCESS", 7, 0);

	}else if(strcmp(arguments[0], "EXIT") == 0){
		int t;
		for(t=0;t<hostIndex;t++){
			if(hosts[t].hostsockfd == calling_client){
				close(hosts[t].hostsockfd);
				FD_CLR(hosts[t].hostsockfd, &master_list);
				if(t == 3){
					hostIndex--;
					break;
				}
				for(int j=t+1;j<hostIndex;j++){
					hosts[j-1] = hosts[j];
				}
				hostIndex--;

				break;
			}
		}
	}else if(strcmp(arguments[0], "LOGOUT") == 0){
		for(int i=0;i<hostIndex;i++){
			if(hosts[i].hostsockfd == calling_client){
				close(hosts[i].hostsockfd);
				FD_CLR(hosts[i].hostsockfd, &master_list);
				hosts[i].status = logout;
				break;
			}
		}
	}


}

/*
* Start select for cmd and connecting.
*/
void start(void){
	char *argm[5];

	FD_ZERO(&master_list);
	FD_ZERO(&watch_list);
	FD_SET(STD_IN, &master_list);
	FD_SET(socketfd, &master_list);
	maxfd = socketfd;

	while (1) {
		watch_list = master_list;
		if(select(maxfd+1, &watch_list, NULL, NULL, NULL) == -1){
			return;
		}

		for(int i=0 ;i < maxfd+1; i++){
			if(FD_ISSET(i, &watch_list)){
				// collect input
				if(i == STD_IN){
					char *cmd = (char *)malloc(sizeof(char)*CMD_LEN);
					memset(cmd, '\0', CMD_LEN);
					fgets(cmd, CMD_LEN-1, stdin);
					for(int j =0; j<CMD_LEN; j++){
						if(cmd[j] == '\n'){
							cmd[j] = '\0';
							break;
						}
					}

					int count = 0;
					char *tmp = strtok(cmd, " ");
					while(tmp != NULL){
						argm[count++] = tmp;
						tmp = strtok(NULL, " ");
					}

					shellCmds(argm, count);

				}else if(i == socketfd && isServer == 1){
					// process new hosts, use a data structure to store info
					struct sockaddr_storage remoteaddr;
					socklen_t len = sizeof(remoteaddr);
					int newfd = accept(socketfd, (struct sockaddr *)&remoteaddr, &len);
					if(newfd == -1){
						continue;
					}
					FD_SET(newfd, &master_list);
					maxfd = maxfd > newfd? maxfd: newfd;

					char clientPort[PORTSTRLEN];
					// bug: different length between client and server
					recv(newfd, clientPort, PORTSTRLEN, 0);
					char tmp[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &(((struct sockaddr_in *)&remoteaddr)->sin_addr), tmp, INET_ADDRSTRLEN);
					struct hostent *he;
					struct in_addr ipv4addr;
					inet_pton(AF_INET, tmp, &ipv4addr);
					he = gethostbyaddr(&ipv4addr, sizeof(struct in_addr), AF_INET);
					int exist = 0;
					for(int i=0;i<hostIndex;i++){
						if(strcmp(hosts[i].ip_addr, tmp) == 0){
							exist = 1;
							hosts[i].status = login;
							break;
						}
					}
					if(!exist){
						struct host newhost;
						newhost.hostsockfd = newfd;
						strcpy(newhost.ip_addr, tmp);
						//newhost.portNum = ((struct sockaddr_in *)&remoteaddr)->sin_port;
						newhost.portNum = strToInt(clientPort);
						strcpy(newhost.hostname, he->h_name);
						newhost.msg_sent = 0;
						newhost.msg_received = 0;
						newhost.status = login;
						newhost.blockindex = 0;
						hosts[hostIndex++] = newhost;
					}
					// sort the array
					if(hostIndex > 1){
						for(int cur = 0; cur< hostIndex-1; cur++){
							for(int fast = cur+1; fast<hostIndex; fast++){
								if(hosts[cur].portNum > hosts[fast].portNum){
									struct host tmp = hosts[cur];
									hosts[cur] = hosts[fast];
									hosts[fast] = tmp;
								}
							}
						}
					}
					// afterwards redirect the array to newly connected client
					char list[BUFLEN] = "";
					packList(list);
					send(newfd, list, BUFLEN, 0);


					//prepare buffered msg for that client
					int count = 0;
					char *bufmsg[BUFLEN];
					char *p;
					p = strtok(bufferedmsg, "---");
					while (p!=NULL) {
						bufmsg[count++] = p;
						p = strtok(NULL, "---");
					}

					char newBufmsg[BUFLEN]="";
					char msgtosend[BUFLEN]="";

					int flag = 0;
					for (int i=0; i<count; ) {
						if (strcmp(tmp, bufmsg[i]) == 0) {
							if(flag == 0){
								strcat(msgtosend, "BROADCAST,");
								strcat(msgtosend, "---");
								flag = 1;
							}
							strcat(msgtosend, bufmsg[i+1]);
							strcat(msgtosend, "---");
							strcat(msgtosend, bufmsg[i+2]);
							strcat(msgtosend, "---");
							cse4589_print_and_log("[%s:SUCCESS]\n", "RELAYED");							
							cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", bufmsg[i+1], bufmsg[i], bufmsg[i+2]);							
							cse4589_print_and_log("[%s:END]\n", "RELAYED");
							
							i+=3;
						} else if(strcmp(bufmsg[i], "255.255.255.255") == 0){
							if(flag == 0){
								strcat(msgtosend, "BROADCAST,");
								strcat(msgtosend, "---");
								flag = 1;
							}
							strcat(newBufmsg, "255.255.255.255");
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
						} else{
							strcat(newBufmsg, bufmsg[i++]);
							strcat(newBufmsg, "---");
							strcat(newBufmsg, bufmsg[i++]);
							strcat(newBufmsg, "---");
							strcat(newBufmsg, bufmsg[i++]);
							strcat(newBufmsg, "---");
						}
					}
					strcpy(bufferedmsg, newBufmsg);
			
					send(newfd, msgtosend, BUFLEN, 0);

				}else if(isServer == 0 && i == clientsockfd){
					char buf[BUFLEN];
					int databytes = recv(i, buf, sizeof buf, 0);
					
					char flag[10]="";

					if(databytes > 1){
						trncpy(flag, buf, 10);
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

						for(int i=1;i<count;){
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
					ssize_t databytes = recv(i, buf, sizeof buf, 0);
					buf[databytes] = '\0';

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

					//debug
					//printf("%s\n%s\n", msg, arguments[count]);

				// for(int l = 0; l < count; l++){
				//	printf("%s--- ", arguments[l]);
					//}
					//printf("\n");

					server_response(arguments,count, i); // second argument was count
					// recv from connected socket, also need to consider argument,send, refresh or block.

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
if (argc != 3) {
	printf("usage: ./chat_app s/c #port\n");
	return 1;
}

if(strcmp(argv[1], "s")==0) isServer = 1;
else if(strcmp(argv[1], "c")==0) isServer = 0;
else return -1; //invalid argument
strcpy(lis_port, argv[2]);

prep(argv[2]);
start();

return 0;
}