#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "/usr/include/openssl/ssl.h"

#define HOST "localhost"
#define PORT 8765
#define CA_PUBLIC "568ca.pem"
#define CLIENT_KEY "alice.pem"
#define PASSWORD "password"
#define COMMON_NAME "Bob's Server"

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

int main(int argc, char **argv)
{
  int len, sock, port=PORT;
  char *host=HOST;
  struct sockaddr_in addr;
  struct hostent *host_entry;
  char buf[256];
  char *secret = "What's the question?";
  SSL_CTX *ctx;
  
  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 3:
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
  fprintf(stderr,"invalid port number");
  exit(0);
      }
      break;
    default:
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }
  
  /*get ip address of the host*/
  
  host_entry = gethostbyname(host);
  
  if (!host_entry){
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }

  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);
  
  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);
  
  /*open socket*/
  
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
    perror("socket");
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
    perror("connect");
  
  send(sock, secret, strlen(secret),0);
  len = recv(sock, &buf, 255, 0);
  buf[len]='\0';
  
  /* connected to TCP socket */
  /* connect to SSL */
  
  /* set up the context and make and set the options to use the correct protocols*/
  ctx = NULL;

  SSL *ssl;
  BIO *sbio;

  ssl = SSL_new(ctx);
  sbio = BIO_new_socket(sock, BIO_NOCLOSE); 
  SSL_set_bio(ssl, sbio, sbio);

  if(SSL_connect(ssl)<= 0){
	berr_exit(FMT_CONNECT_ERR);
  }

  /* SSL connection established */


  /* this is how you output something for the marker to pick up */
  printf(FMT_OUTPUT, secret, buf);
  
  close(sock);
  return 1;
}

void closeSSL(){
  //implement handling of the ssl shutdown and ssl free check the return result of ssl shutdown
  
}
void check_certificate(SSL *ssl, char *common_name, char * server_email){
	// this function is based off of the check_cert function from https://www.linuxjournal.com/files/linuxjournal.com/linuxjournal/articles/048/4822/4822l2.html
	X509 *peer_cert;
	char peer_CN[256];
	char peer_email[256];
	char cert_issuer[256];
	
	/* verify certificate */
	if(SSL_get_verify_result(ssl) != X509_V_OK){
		berr_exit(FMT_NO_VERIFY);
	}
	
	peer_cert = SSL_get_peer_certificate(ssl);
	
	/* check common name */
	X509_NAME_get_text_by_NID(X509_get_subject_name(peer_cert), NID_commonName, peer_CN, 256);
	if(strcasecmp(peer_CN, common_name)){
		err_exit(FMT_CN_MISMATCH);
	}
	
	/* check server email */
	X509_NAME_get_text_by_NID(X509_get_subject_name(peer_cert), NID_pkcs9_emailAddress, peer_email, 256);
	if(strcasecmp(peer_email, server_email)){
		err_exit(FMT_EMAIL_MISMATCH);
	}
	
	/* get certificate issuer */
	X509_NAME_get_text_by_NID(X509_get_issuer_name(peer_cert), NID_commonName, cert_issuer, 256);
	
	printf(FMT_SERVER_INFO, peer_CN, peer_email, cert_issuer);
}
