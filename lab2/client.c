#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

#define HOST "localhost"
#define PORT 8765
#define CA_PUBLIC "568ca.pem"
#define CLIENT_KEY "alice.pem"
#define PASSWORD "password"
#define COMMON_NAME "Bob's Server"
#define CIPHER "SHA1"
#define SERVER_EMAIL "ece568bob@ecf.utoronto.ca"
#define BUFFER_SIZE 256

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

void closeSSLConnection(int sock, SSL *ssl){

  //implement handling of the ssl shutdown and ssl free check the return result of ssl shutdown
  int r = SSL_shutdown(ssl);
  if(!r) {
    /* If we called SSL_shutdown() first then
     we always get return value of '0'. In
     this case, try again, but first send a
     TCP FIN to trigger the other side's
     close_notify*/
    shutdown(sock, 1);
    r = SSL_shutdown(ssl);
  }

  if (r!=1)
    err_exit(FMT_INCORRECT_CLOSE);

  SSL_free(ssl);
  close(sock);
}

void check_certificate(SSL *ssl, char *common_name, char * server_email){
	// this function is based off of the check_cert function from https://www.linuxjournal.com/files/linuxjournal.com/linuxjournal/articles/048/4822/4822l2.html
	X509 *peer_cert;
	char peer_CN[BUFFER_SIZE];
	char peer_email[BUFFER_SIZE];
	char cert_issuer[BUFFER_SIZE];
	
	/* verify certificate */
	if(SSL_get_verify_result(ssl) != X509_V_OK){
		berr_exit(FMT_NO_VERIFY);
	}
	
	peer_cert = SSL_get_peer_certificate(ssl);
	
	/* check common name */
	X509_NAME_get_text_by_NID(X509_get_subject_name(peer_cert), NID_commonName, peer_CN, BUFFER_SIZE);
	if(strcasecmp(peer_CN, common_name)){
		err_exit(FMT_CN_MISMATCH);
	}
	
	/* check server email */
	X509_NAME_get_text_by_NID(X509_get_subject_name(peer_cert), NID_pkcs9_emailAddress, peer_email, BUFFER_SIZE);
	if(strcasecmp(peer_email, server_email)){
		err_exit(FMT_EMAIL_MISMATCH);
	}
	
	/* get certificate issuer */
	X509_NAME_get_text_by_NID(X509_get_issuer_name(peer_cert), NID_commonName, cert_issuer, BUFFER_SIZE);
	
	printf(FMT_SERVER_INFO, peer_CN, peer_email, cert_issuer);
}

void read_write(SSL *ssl, char *secret, char *output){
	/* write request */
	int write_res;
	
	write_res = SSL_write(ssl, secret, strlen(secret));
	switch(SSL_get_error(ssl, write_res)){
		case SSL_ERROR_NONE:
			if(strlen(secret) != write_res){
				err_exit("SSL write was not completed");
			}
			break;
		default:
			berr_exit("SSL write encountered problem");
	}
	
	/* read response */
	int read_res;
	read_res = SSL_read(ssl, output, BUFFER_SIZE);
	if(read_res < 0){
		berr_exit("SSL read encountered problem");
	}
	
	output[read_res] = '\0';
}

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
  ctx = initialize_ctx(CLIENT_KEY, PASSWORD);
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
  SSL_CTX_set_cipher_list(ctx,CIPHER);

  SSL *ssl;
  BIO *sbio;

  ssl = SSL_new(ctx);
  sbio = BIO_new_socket(sock, BIO_NOCLOSE); 
  SSL_set_bio(ssl, sbio, sbio);

  if(SSL_connect(ssl)<= 0){
	berr_exit(FMT_CONNECT_ERR);
  }

  /* check certificate */
  check_certificate(ssl, COMMON_NAME, SERVER_EMAIL);

  /* handle SSL read and write */
  read_write(ssl, secret, buf);
  
  /* this is how you output something for the marker to pick up */
  printf(FMT_OUTPUT, secret, buf);
  
  closeSSLConnection(sock, ssl);
  return 1;
}


