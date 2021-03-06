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
#include <stdbool.h>
#define FAIL    -1

/*based on martin broadhursts tcp proxy code*/
int OpenListener(const char* host, const char* port)
{   int sd;
    int reuseaddr = 1;
    struct addrinfo hints, *res;
    /* Get the address info */
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) {
        perror("getaddrinfo");
        return 1;
    }

    /* Create the socket */
    sd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sd == -1) {
        perror("socket");
        freeaddrinfo(res);
        return 1;
    }

    /* Enable the socket to reuse the address */
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int)) == -1) {
        perror("setsockopt");
        freeaddrinfo(res);
        return 1;
    }

    /* Bind to the address */
    if (bind(sd, res->ai_addr, res->ai_addrlen) == -1) {
        perror("bind");
        freeaddrinfo(res);
        return 1;
    }

    /* Listen */
    if (listen(sd, 10) == -1) {
        perror("listen");
        freeaddrinfo(res);
        return 1;
    }

    freeaddrinfo(res);
    return sd;
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

/*get certificates if possible*/
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl);
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

/*recieves a requested number of ecents to create
  generates strings of 32 random characters which are added to bankecents.txt
  each ecent is appended to a large string separated by spaces and returned*/
char * createeCents(int ecentnum){
    char ecents[ecentnum*33];
    ecents[0] = '\0';
    char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    FILE *fw;
    fw = fopen ("bankecents.txt", "a");
    int n;
    while(ecentnum > 0)
    {
        char ecent[33];
        for (n = 0; n < 32; n++) {
            int key = rand() % (int) (sizeof charset - 1);
            ecent[n] = charset[key];
        }
        ecent[32] = '\0';
        fprintf(fw,"%s\n", ecent);
        sprintf(ecents,"%s%s ", ecents, ecent);
        printf("new ecent: %s\n", ecent);
        ecentnum--;
    }
    ecents[ecentnum*33-1] = '\0';
    fclose(fw);
    return ecents;
}

/*checks that an ecent matches a previously made request
  function opens bankecents.txt, a list of every active ecent,
  if the corresponding ecent is found remove it from the file 
  and create and return a new one*/
char * verifyeCent(char *ecent){
    bool verified = false;
    char line[80];
    FILE *fr;
    FILE *fw;
    fr = fopen ("bankecents.txt", "rt");
    fw = fopen ("newbankecents.txt", "w");
    while(fgets(line, 80, fr) != NULL)
    {
        line[32] = '\0';
        if(strcmp(ecent, line) == 0){
            verified = true;
        }
        else{
            fprintf(fw,"%s\n", line);
        }
    }
    fclose(fw);
    fclose(fr);
    rename("newbankecents.txt", "bankecents.txt");
    if(verified){
        printf("---eCent Confirmed---\n");
        return createeCents(1);
    }
    else
        printf("---eCent Denied---\n");
        return "";
}

void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{
    char buf[1024];
    char reply[1024];
    char reply2[33000];
    reply[0] = '\0';
    int sd, bytes;
 
    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        ShowCerts(ssl);        /* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        if ( bytes > 0 )
        {
            /*separate buf into parts: 
                first char: action (which function to be performed)
                remaining chars: input for function*/
            buf[bytes] = 0;
            char action = buf[0];
            memmove(buf, buf+1, strlen(buf));
            printf("Received message from Client: %s\n", buf);
            if(action == '0'){
                printf("action: create %s eCents\n", buf);
                int ecentnum = atoi(buf);
                strcpy(reply2, createeCents(ecentnum));
                printf("response: %s\n", reply2);
                SSL_write(ssl, reply2, ecentnum*33);
            }
            else {
                printf("verify eCent: %s\n", buf);
                char* ecent = malloc(32);
                strcpy(ecent, buf);
                strcpy(reply, verifyeCent(ecent));
                SSL_write(ssl, reply, strlen(reply));
                printf("response: %s\n", reply);
            }
	   
        }
        else
            ERR_print_errors_fp(stderr);
    }
    sd = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sd);
}
 
int main(int argc, char *argv[])
{
    remove("bankecents.txt");
    SSL_CTX *ctx;
    int server;
    const char * localport;
    const char * localhost;
 
    if ( argc < 2 ){
        printf("Usage:server localhost localport \n");
        exit(0);
    }
    SSL_library_init();
    localhost = argv[1];
    localport = argv[2];
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "mycert2.pem", "mycert2.pem"); /* load certs */
    server = OpenListener(localhost, localport);    /* create server socket */
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
