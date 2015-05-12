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
    method = SSLv3_server_method();  /* create new server-method instance */
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
 
void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{   char buf[1024];
    char reply[1024];
    int sd, bytes;
    //const char* HTMLecho="<html><body><pre>%s</pre></body></html>\n\n";
 
    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        ShowCerts(ssl);        /* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        if ( bytes > 0 )
        {
            buf[bytes] = 0;
            printf("Received message from Client: %s\n", buf);
            //sprintf(reply, HTMLecho, buf);   /* construct reply */
	    printf("Here is your message: ");
	    fgets(reply, 1024, stdin); 
            SSL_write(ssl, reply, strlen(reply)); /* send reply */
        }
        else
            ERR_print_errors_fp(stderr);
    }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
}
 
int main(int argc, char *argv[])
{   
    SSL_CTX *ctx;
    int server, localport, proxyport;
    char *proxyhost;
 
    if(!isRoot()){
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    if ( argc < 3 ){
        printf("Usage:server localport proxyhost proxyport \n");
        exit(0);
    }
    SSL_library_init();
 
    localport = atoi(argv[1]);
    proxyhost = argv[2];
    proxyport = atoi(argv[3]);
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */
    registrationrequest( localport, proxyhost, proxyport);
    server = OpenListener(localport);    /* create server socket */
    while (1)
    {   struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
 
        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
        Servlet(ssl);         /* service connection */
    }
    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}
