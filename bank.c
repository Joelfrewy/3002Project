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


char * createeCents(int ecentnum){
    char * ecents = malloc(ecentnum*33);
    char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    FILE *fw;
    fw = fopen ("bankecents.txt", "a");
    while(ecentnum > 0)
    {
        char * ecent = malloc(33);
        for (int n = 0; n < 32; n++) {
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
    int sd, bytes;
 
    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        ShowCerts(ssl);        /* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        if ( bytes > 0 )
        {
            buf[bytes] = 0;
            char action = buf[0];
            memmove(buf, buf+1, strlen(buf));
            printf("Received message from Client: %s\n", buf);
            if(action == '0'){
                printf("action: create %s eCents\n", buf);
                int ecentnum = atoi(buf);
                strcpy(reply, createeCents(ecentnum));
            }
            if(action == '1'){
                printf("verify eCent: %s\n", buf);
                char* ecent = malloc(32);
                strcpy(ecent, buf);
                strcpy(reply, verifyeCent(ecent));
            }
            //sprintf(reply, HTMLecho, buf);   /* construct reply */
	    printf("response: %s\n", reply);
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
    remove("bankecents.txt");
    SSL_CTX *ctx;
    int server, localport;
 
    if ( argc <= 1 ){
        printf("Usage:server localport \n");
        exit(0);
    }
    SSL_library_init();
    localport = atoi(argv[1]);
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "mycert2.pem", "mycert2.pem"); /* load certs */
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
