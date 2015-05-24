
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
 
#define FAIL    -1
	

/*Returns and removes first ecent from ecent.txt */
char * geteCent(){
    if( access( "ecents.txt", F_OK ) == -1 ) {  /* check if ecents.txt exists */
        return "";
    }
    int i = 0;
    char line[80];
    char *ecent = malloc(33);
    FILE *fr;
    FILE *fw;
    fr = fopen ("ecents.txt", "rt");
    fw = fopen ("newecents.txt", "wt");
    while(fgets(line, 80, fr) != NULL)
    {
        if(i == 0){
            strcpy(ecent, line);
        }
        else{
            fprintf(fw,"%s", line);
        }
        i++;
    }
    ecent[32] = '\0';
    fclose(fw);
    fclose(fr);
    rename("newecents.txt", "ecents.txt");
    return ecent;
}

/* prints string of ecents separated by spaces into file "ecents.txt" */
void puteCents(char* ecents){
    char *ecentscpy = malloc(33000);
    strcpy(ecentscpy, ecents);
    FILE *fw;
    fw = fopen ("ecents.txt", "a");
    char* line = strtok(ecentscpy, " ");
    while (line) {
        fprintf(fw,"%s\n", line);
        line = strtok(NULL, " ");
    }
    fclose(fw);
}

/*registration request sends a registration request to the Director */
void registrationrequest(int type, int localport, char* proxyhost, int proxyport ){
   int sockfd;
   struct sockaddr_in local_addr, proxy_addr;
   struct hostent *server;
   
   char buffer[1024];
   
   /* Create socket  */
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   
   if (sockfd < 0){
      perror("ERROR opening socket");
      exit(1);
   }
     server = gethostbyname(proxyhost);

    memset(&local_addr, 0, sizeof(struct sockaddr_in));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(localport);
    local_addr.sin_addr.s_addr = INADDR_ANY;
    int yes = 1;
    if ( setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ){
     	perror("setsockopt");
	exit(1);
    }
    if(bind(sockfd, (struct sockaddr *)&local_addr, sizeof(struct sockaddr)) == -1){
	perror("bind");
	exit(1);
    }
   
   bzero((char *) &proxy_addr, sizeof(proxy_addr));
   proxy_addr.sin_family = AF_INET;
   bcopy((char *)server->h_addr, (char *)&proxy_addr.sin_addr.s_addr, server->h_length);
   proxy_addr.sin_port = htons(proxyport);
	
   char outbuf[4];

   outbuf[0] = '\0';
   /* Send 0 (Collector) and type */
   sprintf(outbuf, "0%i", type);
   printf( "outbuf is %s\n", outbuf);
   bzero(buffer,1024);
   	/* Connect to Director */
   if (connect(sockfd, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) < 0){
    	  perror("ERROR connecting to director");
    	  exit(1);
   	}

   
   /* Send message to director */
   if(write(sockfd, outbuf, 4)<0){
	perror("Socket write error");
	exit(1);
   }
   
   /* Read Director response */
   if(read(sockfd, buffer, 1023)<0){
      perror("Socket write error");
      exit(1);
   }
   printf("Received message from Director: %s\n",buffer);
   close(sockfd);
}

/* creates socket and opens connection from collector to director */
int OpenConnection(const char *hostname, int clientport, int serverport)
{   int sd;
    struct hostent *host;
    struct sockaddr_in serv_addr, cli_addr;
 
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        exit(1);
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);

    bzero(&serv_addr, sizeof(serv_addr));
    
    memset(&cli_addr, 0, sizeof(struct sockaddr_in));
    cli_addr.sin_family = AF_INET;
    cli_addr.sin_port = htons(clientport);
    cli_addr.sin_addr.s_addr = INADDR_ANY;
    
    int yes = 1;
    if ( setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ){
     	perror("setsockopt");
	exit(1);
    }

    if(bind(sd, (struct sockaddr *)&cli_addr, sizeof(struct sockaddr)) == -1){
	perror("bind");
	exit(1);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(serverport);
    serv_addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}
 /* Based on SSL_Tutorial code from http://simplestcodings.blogspot.com.au/2010/08/secure-server-client-using-openssl-in-c.html */
SSL_CTX* InitCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;
 
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = SSLv3_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
 
/* Based on SSL_Tutorial code from http://simplestcodings.blogspot.com.au/2010/08/secure-server-client-using-openssl-in-c.html */
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("No certificates.\n");
}

void wait(unsigned int secs){
    int endtime = time(0) + secs;
    while(time(0) < endtime);
}
/*generates data */
char *getData(){
    int n = 0;
    char *data = malloc(20);
    data[0] = '\0';
    while(n < 5){
	wait(2);
	int number = rand()%100+1;
	printf("\t%i\n", number);
	sprintf(data, "%s %i", data, number);
	n++;
    }
    printf("\n");
    wait(2);
    data[strlen(data)] = '\0';
    return data;
}

int main(int argc, char *argv[])
{
    /* deletes existeng ecents */
    remove("ecents.txt");
    SSL_CTX *ctx;
    int type, server, localport, proxyport, bankport;
    int i = 0;
    SSL *ssl;
    char buf[1024];
	char buf2[33000];
    int bytes;
    char *proxyhost;
    char *bankhost;
    
    if ( argc <6 )
    {
        printf("usage: type localport proxyhost proxyport bankhost bankport \n");
        exit(0);
    }
    /* initialises SSL library and copies line arguments */
    SSL_library_init();
    type = atoi(argv[1]);
    localport=atoi(argv[2]);
    proxyhost=argv[3];
    proxyport = atoi(argv[4]);
    bankhost = argv[5];
    bankport = atoi(argv[6]);
    registrationrequest(type, localport, proxyhost, proxyport);
    int requestedecents = 1000;
    
    
    while(1){
        char msg[1024];
        bzero(msg,1024);
        ctx = InitCTX();
        if(i == 0){
            printf("\nrequested number of eCents: \n");
	    wait(3);
	    printf("\t%i\n", requestedecents);
	    wait(3);
            sprintf(msg,"%c%i",'0',requestedecents);
	        server = OpenConnection(bankhost, localport, bankport);
        }
        else{
            printf("\ninput:\n");
            strcpy(msg, geteCent());
            if(strlen(msg) != 32){
                printf("no eCents\n");
            }
            else {
                strcat(msg, getData());
                server = OpenConnection(proxyhost, localport, proxyport);
            }
        }
	/* creates ssl context and sets socket to it*/
        ssl = SSL_new(ctx);      
        SSL_set_fd(ssl, server);   
        if ( SSL_connect(ssl) == -1 ){  
            ERR_print_errors_fp(stderr);
	    printf("connection error\n");
	}
        else
        {
            printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
            printf("sending: %s\n", msg);
            ShowCerts(ssl);  
		/* Write to Bank to verify ecent */  
            SSL_write(ssl, msg, sizeof(msg));  
            
            if(i == 0){
		bzero(buf2, 33000);
		/* Read from Bank, confirm verification*/
		bytes = SSL_read(ssl, buf2, sizeof(buf2)); 
		if(bytes < 1) 
		{
			printf("Exit read error from Bank\n");
			exit(1);
		}
            	buf2[bytes] = '\0';
                printf("eCents received: %s\n", buf2);
                puteCents(buf2);
            }
            else{
		/* Reads from Collector*/
		bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
            	buf[bytes] = '\0';
		if(bytes < 1) 
		{
			printf("Exit: read error from Analyst\n");
			exit(1);
		}
                if(strcmp(buf, "invalid eCent") == 0)
                    printf("\n%s\n", buf);
                else
                    printf("\naverage: %s\n", buf);
            }
            SSL_free(ssl);        
        }
        sleep(1);
        close(server);         
        SSL_CTX_free(ctx);       
        i++;
    }
    return 0;
}
