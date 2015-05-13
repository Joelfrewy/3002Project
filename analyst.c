//SSL-Server.c
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
 
#define FAIL    -1

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

void registrationrequest(int localport, char* proxyhost, int proxyport ){
   int sockfd;
   struct sockaddr_in local_addr, proxy_addr;
   struct hostent *server;
   
   char buffer[1024];
   
   /* Create a socket point */
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
   bzero(outbuf, 4);
   outbuf[0] = '1';
   outbuf[1] = '0';
   bzero(buffer,1024);
   	/* Now connect to the server */
   if (connect(sockfd, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) < 0){
    	  perror("ERROR connecting to proxy");
    	  exit(1);
   	}
   
   /* Now ask for a message from the user, this message
   * will be read by server
   */

   
   /* Send message to the server */
   if(write(sockfd, outbuf, 4)<0){
	perror("Socket write error");
	exit(1);
   }
   
   /* Now read server response */
   if(read(sockfd, buffer, 1023)<0){
      perror("Socket wrte error");
      exit(1);
   }
   printf("Received message from Proxy: %s\n",buffer);
   close(sockfd);
}
 
int OpenListener(int port)
{   int sd;
    struct sockaddr_in addr;
 
    sd = socket(PF_INET, SOCK_STREAM, 0);
    
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    int yes = 1;
    if ( setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ){
     	perror("setsockopt");
    }
    if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        exit(1);
    }
    if ( listen(sd, 0) != 0 )
    {
        perror("Can't configure listening port");
        exit(1);
    }
    return sd;
}
 
int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
 
}
SSL_CTX* InitServerCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;
 
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = SSLv3_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
 
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}
 
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}
 
void Servlet(SSL *ssl,SSL *ssl2, int client, int bank) /* Serve the connection -- threadable */		void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{   char bufclient[1024];		{   char buf[1024];
    char sendtobank[1024];		    char reply[1024];
    char replyclient[1024];		    int sd, bytes;
    char replybank[1024];		    //const char* HTMLecho="<html><body><pre>%s</pre></body></html>\n\n";
    int bytes1, bytes2;
    const char* HTMLecho="<html><body><pre>%s</pre></body></html>\n\n";
    SSL_set_fd(ssl, client);
    SSL_set_fd(ssl2, bank);
    SSL_set_accept_state(ssl);
    SSL_set_connect_state(ssl2);
 		 
    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */		    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);		        ERR_print_errors_fp(stderr);
    else		    else
    {		    {
        ShowCerts(ssl);        /* get any certificates */		        ShowCerts(ssl);        /* get any certificates */
        bytes1 = SSL_read(ssl, bufclient, sizeof(bufclient)); /* get request */		        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        if ( bytes1 > 0 )		        if ( bytes > 0 )
        {		        {
            bufclient[bytes1] = 0;		            buf[bytes] = 0;
            printf("Received message from Collector: %s\n", bufclient);		            printf("Received message from Client: %s\n", buf);
            if (SSL_connect(ssl2) == FAIL){
                printf("SSL_connect fail\n");
                ERR_print_errors_fp(stderr);
            }
            //sprintf(reply, HTMLecho, buf);   /* construct reply */		            //sprintf(reply, HTMLecho, buf);   /* construct reply */
            strcpy(sendtobank, "From Collector: ");			    printf("Here is your message: ");
            strcat(sendtobank, bufclient);			    fgets(reply, 1024, stdin);
            ShowCerts(ssl2);		            SSL_write(ssl, reply, strlen(reply)); /* send reply */
            printf("Sending Message to Bank: %s\n", sendtobank);
            SSL_write(ssl2, sendtobank, sizeof(sendtobank));
            bytes2 = SSL_read(ssl2, replybank, sizeof(replybank)); /* get reply & decrypt */
            if(bytes2 > 0){
                replybank[bytes2] = 0;
                printf("Received message from Bank %s\n", replybank);
            }
            else {
                ERR_print_errors_fp(stderr);
            }
            SSL_free(ssl2);
            printf("Here is your message to Collector: ");
            fgets(replyclient, 1024, stdin);
            SSL_write(ssl, replyclient, strlen(replyclient)); /* send reply */
        }		        }
        else		        else
            ERR_print_errors_fp(stderr);		            ERR_print_errors_fp(stderr);
    }		    }
    /* get socket connection */		    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */		    SSL_free(ssl);         /* release SSL state */
    close(client);          /* close connection */		    close(sd);          /* close connection */
    close(bank);
}		}

int main(int argc, char *argv[])		int main(int argc, char *argv[])
{   		{
    SSL_CTX *ctx;		    SSL_CTX *ctx;
    int server, listenport, connectport, proxyport, bankport;		    int server, localport, proxyport;
    char *proxyhost;		    char *proxyhost;
    char *bankhost;
 		 
    if(!isRoot()){		    if(!isRoot()){
        printf("This program must be run as root/sudo user!!");		        printf("This program must be run as root/sudo user!!");
        exit(0);		        exit(0);
    }		    }
    if ( argc < 6 ){		    if ( argc < 3 ){
        printf("Usage:server listenport connectport proxyhost proxyport bankhost bankport\n");		        printf("Usage:server localport proxyhost proxyport \n");
        exit(0);		        exit(0);
    }		    }
    SSL_library_init();		    SSL_library_init();
 		 
    listenport = atoi(argv[1]);		    localport = atoi(argv[1]);
    connectport = atoi(argv[2]);		    proxyhost = argv[2];
    proxyhost = argv[3];		    proxyport = atoi(argv[3]);
    proxyport = atoi(argv[4]);
    bankhost = argv[5];
    bankport = atoi(argv[6]);
    ctx = InitServerCTX();        /* initialize SSL */		    ctx = InitServerCTX();        /* initialize SSL */
    registrationrequest( listenport, proxyhost, proxyport);		    LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */
    server = OpenListener(listenport);    /* create server socket */		    registrationrequest( localport, proxyhost, proxyport);
    server = OpenListener(localport);    /* create server socket */
    while (1)		    while (1)
    {   struct sockaddr_in addr;		    {   struct sockaddr_in addr;
        socklen_t len = sizeof(addr);		        socklen_t len = sizeof(addr);
        SSL *ssl;		        SSL *ssl;
        SSL *ssl2;
        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */		        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        int bank = OpenConnection(bankhost, connectport, bankport);
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));		        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl2 = SSL_new(ctx);              /* get new SSL state with context */		        ssl = SSL_new(ctx);              /* get new SSL state with context */
        LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */		        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
        ssl = SSL_new(ctx);		        Servlet(ssl);         /* service connection */
        Servlet(ssl, ssl2, client, bank);         /* service connection */
    }		    }
    close(server);          /* close server socket */		    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */		    SSL_CTX_free(ctx);         /* release context */
}