/* 
 *  A simple TCP proxy
 *  by Martin Broadhurst (www.martinbroadhurst.com)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memset() */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/mman.h>


#define PORT     "32002" /* Port to listen on */
#define BACKLOG  10      /* Passed to listen() */
#define BUF_SIZE 4096    /* Buffer for  transfers */
#define MAX_ANALYSTS 10
#define MAX_COLLECTORS 10
#define MAX_EITHER 10

const char *AnalystsAddr[MAX_ANALYSTS];
const char *CollectorsAddr[MAX_COLLECTORS]; /* I hate passing Globals but I needed to */
int AnalystsPIDTYPE[3][MAX_ANALYSTS];
int CollectorsPIDTYPE[3][MAX_COLLECTORS];
int cindex, aindex;

void pipehandle( int readpipefd, const char* host, int port){
	char inbuffer[4];
	//bzero(inbuffer, 4);
	if(read( readpipefd,inbuffer, 4 )==-1){
		perror("Error reading pipehandle\n");
	}

	int inbuf1 = inbuffer[0] - 48;
	int inbuf2 = inbuffer[1] - 48;
	//printf("do I still exist?\n");
	printf("Player is : %c\n", inbuffer[0]);
	if(inbuf1 == 0){
		cindex++;
		CollectorsAddr[cindex] = host;
		CollectorsPIDTYPE[0][cindex] = port;
		CollectorsPIDTYPE[2][cindex] = inbuf2;
		printf("Collector was Registered at Host: %s Port: %d of Type: %d / %c \n", host, port, inbuf2, inbuffer[1]);		
	}
	else if( inbuf1 == 1){
		aindex++;
		char *hostcopy = malloc(100);
		strcpy(hostcopy, host);
		AnalystsAddr[aindex] = hostcopy;
		//printf("Host is %s\n", AnalystAddr[aindex]);
		AnalystsPIDTYPE[0][aindex] = port;
		AnalystsPIDTYPE[2][aindex] = inbuf2;
		AnalystsPIDTYPE[1][aindex] = 0;
		printf("Analyst was Registered at Host: %s Port: %d of Type: %d / %c \n", host, port, inbuf2, inbuffer[1]);
	}
	else {
		perror("Error: Could not read registration packet");
	}
	//printf("Player is : %c\n", inbuffer[0]);
	close(readpipefd);
}

void unregisteredhandle( int sockfd, int writepipefd){
	char inbuffer[4];
	char outbuffer[1024];
	bzero(inbuffer,4);
	bzero(outbuffer,1024);
	sprintf(outbuffer, "Registered");
    	if(read( sockfd,inbuffer, 4 )==-1){
		perror("Error reading unregisteredhandle\n");
	}
   	if(write(sockfd,outbuffer,1024)== -1){
   		perror("Error writing unregisteredhandle\n");
	}
	if(write(writepipefd,inbuffer,4)== -1){
   		perror("Error writing to Pipe, unregisteredhandle\n");
	}
	close(writepipefd);
	close(sockfd);
} 

int isregistered( const char *host, int port){
	int j = 0;
	int registered = -1;
	for( j = 0; j< MAX_COLLECTORS; j++){
		if(CollectorsPIDTYPE[0][j] == port){
			//printf("Same Port! Host is %s and Registered host is %s\n", host, CollectorsAddr[j] );
			if(strncmp(CollectorsAddr[j], host, strlen(host)) == 0){
				return 0;
				printf("Registered Collector\n");
			}
		}
	}
	if (registered != 0){
		for( j = 0; j< MAX_ANALYSTS; j++){
			if(AnalystsPIDTYPE[0][j] ==  port){
				if(strncmp(AnalystsAddr[j], host, strlen(host)) == 0){
					return 1;
					printf("Registered Analyst\n");
				}
			}
		}
	}
	return -1;
}

int getType(const char *host, int port)
{
	int j = 0;
	for( j = 0; j< MAX_COLLECTORS; j++){
		if(CollectorsPIDTYPE[0][j] == port){
			if(strncmp(CollectorsAddr[j], host, strlen(host)) == 0){
				return CollectorsPIDTYPE[2][j];
			}
		}
	}
	return -1;
}

	 

int choose(int type)
{
    int i;
    for(i=0 ; i< MAX_ANALYSTS; i++){
	if((AnalystsPIDTYPE[1][i] == 0)&&(AnalystsPIDTYPE[2][i]==type)){
		printf("Analyst chosen was Host: %s Port: %d of type %d at index %d \n",AnalystsAddr[i], AnalystsPIDTYPE[0][i], type, i);
		return i;
	}
    }
    return -1;
}

unsigned int transfer(int from, int to)
{
    char buf[BUF_SIZE];
    unsigned int disconnected = 0;
    size_t bytes_read, bytes_written;
    bytes_read = read(from, buf, BUF_SIZE);
    if (bytes_read < 5) {
        disconnected = 1;
    }
    else {
        bytes_written = write(to, buf, bytes_read);
        if (bytes_written == -1) {
            disconnected = 1;
        }
	else {
		    printf("\n (NSA) Redirected message: %s%i\n", buf, bytes_read);
	}
    }
    return disconnected;
}

void registeredhandle(int client, const char *host, int port)
{
    struct addrinfo hints, *res;
    int server = -1;
    unsigned int disconnected = 0;
    fd_set set;
    unsigned int max_sock;
    //printf("handle 1\n");
    char buf[32];
    sprintf(buf, "%d", port);
    /* Get the address info */
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, buf, &hints, &res) != 0) {
        perror("getaddrinfo");
        close(client);
        return;
    }

    /* Create the socket */
    server = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (server == -1) {
        perror("socket");
        close(client);
        return;
    }
    //printf("handle 2\n");
    /* Connect to the host */
    if (connect(server, res->ai_addr, res->ai_addrlen) == -1) {
        perror("connect");
        close(client);
        return;
    }

    if (client > server) {
        max_sock = client;
    }
    else {
        max_sock = server;
    }
    //printf("handle 3\n");
    /* Main transfer loop */
    while (!disconnected) {
        FD_ZERO(&set);
        FD_SET(client, &set);
        FD_SET(server, &set);
        //printf("handle 4\n");
        if (select(max_sock + 1, &set, NULL, NULL, NULL) == -1) {
	    
            perror("select");
            break;
        }
        if (FD_ISSET(client, &set)) {
	    printf("client-server connection\n");
            disconnected = transfer(client, server);
        }
        if (FD_ISSET(server, &set)) {
	    printf("server-client connection\n");
            disconnected = transfer(server, client);
        }
	    //printf("handle 5\n");
    }
    close(server);
    close(client);
}

int main(int argc, char **argv)
{
    int sock, port, type;
    struct addrinfo hints, *res;
    int reuseaddr = 1; /* True */
    const char * boundhost;
    const char * host;
    const char * boundport;
    cindex = -1;
    aindex = -1;

    /* Get the server host and port from the command line */
    if (argc < 2) {
        perror( "Usage: proxy boundhost boundport\n");
        return 1;
    }
 
    memset(AnalystsAddr, 0, MAX_ANALYSTS);
    memset(CollectorsAddr, 0, MAX_ANALYSTS);
    memset(AnalystsPIDTYPE, -1, sizeof(AnalystsPIDTYPE[0][0])* 3 *MAX_ANALYSTS);
    memset(CollectorsPIDTYPE, -1, sizeof(CollectorsPIDTYPE[0][0])* 3 *MAX_COLLECTORS);

    boundhost = argv[1];
    boundport = argv[2];

    /* Get the address info */
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(boundhost, boundport, &hints, &res) != 0) {
        perror("getaddrinfo");
        return 1;
    }

    /* Create the socket */
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == -1) {
        perror("socket");
        freeaddrinfo(res);
        return 1;
    }

    /* Enable the socket to reuse the address */
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int)) == -1) {
        perror("setsockopt");
        freeaddrinfo(res);
        return 1;
    }

    /* Bind to the address */
    if (bind(sock, res->ai_addr, res->ai_addrlen) == -1) {
        perror("bind");
        freeaddrinfo(res);
        return 1;
    }

    /* Listen */
    if (listen(sock, BACKLOG) == -1) {
        perror("listen");
        freeaddrinfo(res);
        return 1;
    }

    freeaddrinfo(res);

    /* Ignore broken pipe signal */
    signal(SIGPIPE, SIG_IGN);
 
    /* Main loop */
    while (1) {
        unsigned int size = sizeof(struct sockaddr_in);
        struct sockaddr_in their_addr;
	fd_set fdset;
	
	int index, pid, registered;
	int maxfd = sock;
	struct timeval tv = {0,0};
	FD_ZERO(&fdset);
	FD_SET(sock, &fdset);
	//printf("Before Select\n");
	if (select(maxfd + 1, &fdset, NULL, NULL, &tv) < 0) {
	    //printf("what am I doing here???");
            perror("select");
            break;
        }
	//printf("before Accept loop\n");
	if(FD_ISSET(sock, &fdset)){
	//printf("you're in the accept loop!\n");
        int newsock = accept(sock, (struct sockaddr*)&their_addr, &size);
	if (newsock == -1) {
            perror("accept");
        }
	const char *newsockhost = inet_ntoa(their_addr.sin_addr);
	int newsockport = htons(their_addr.sin_port);

	pid = -1;
        int pipefd[2];
	

	registered = isregistered(newsockhost, newsockport);
	//printf("after register\n");
	if(registered == 0){
		type = getType(newsockhost, newsockport);
		if( type == -1){
			perror("getType");
		}
		index = choose(type);
		if(index == -1){
			perror("choose");
		}
		host = AnalystsAddr[index];
		port = AnalystsPIDTYPE[0][index];
	}
	else if (registered == -1){
		if ( pipe(pipefd) == -1){
			perror("pipe");
		}
	}
        if(newsock!=-1) {
   		pid = fork();
      		if (pid < 0)
         	{
         		perror("ERROR on fork");
         		exit(1);
         	}
      
      		if (pid == 0)
         	{
         	/* This is the client process */
         		close(sock);
         		printf("Got a connection from %s on port %d\n", inet_ntoa(their_addr.sin_addr), htons(their_addr.sin_port));
			if(registered == 0){
            			registeredhandle(newsock, host, port);
			}
			else if(registered == -1){
				close(pipefd[0]);
				unregisteredhandle(newsock, pipefd[1]);
                int i = 1;
				wait(&i);
			}
			//printf("I'm exiting now\n");
         		exit(0);
       		  }
      		else {
			close(newsock);
			if( registered == -1){
				close(pipefd[1]);
				pipehandle(pipefd[0], newsockhost, newsockport);
			}
			if ( registered == 0){
				AnalystsPIDTYPE[1][index] = pid;
			}
			printf("PID is: %d\n", pid);
		}
        }
	}
		//printf("listen to me you git\n");
		int status, exitpid, i;
		exitpid = waitpid (-1, &status, WNOHANG);
		if(exitpid<0){
			//perror("waitpid");
		}
		if(exitpid>0){
			printf("Process exited, PID is : %d\n", exitpid);
			for(i = 0; i< MAX_ANALYSTS; i++){
				if(AnalystsPIDTYPE[1][i] == exitpid){
					AnalystsPIDTYPE[1][i] =0;
					break;
				}
			}
		}
    }

    close(sock);
    return 0;
}

