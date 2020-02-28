#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "sslhelpers.h"

#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

#define HOST "localhost"
#define PORT 8765
#define CA_PUBLIC "568ca.pem"
#define SERVER_KEY "bob.pem"
#define PASSWORD "password"
#define COMMON_NAME "Alice's Client"
#define CIPHER "SHA1"
#define SERVER_EMAIL "ece568alice@ecf.utoronto.ca"
#define BUFFER_SIZE 256

void check_certificate(SSL *ssl, char *common_name, char * server_email){
	// this function is based off of the check_cert function from https://www.linuxjournal.com/files/linuxjournal.com/linuxjournal/articles/048/4822/4822l2.html
	X509 *peer_cert;
	char peer_CN[BUFFER_SIZE];
	char peer_email[BUFFER_SIZE];
	char cert_issuer[BUFFER_SIZE];
	
	/* verify certificate */
	if(SSL_get_verify_result(ssl) != X509_V_OK){
		berr_exit(FMT_ACCEPT_ERR);
	}
	
	peer_cert = SSL_get_peer_certificate(ssl);
	
	/* check common name */
	X509_NAME_get_text_by_NID(X509_get_subject_name(peer_cert), NID_commonName, peer_CN, BUFFER_SIZE);
	/*if(strcasecmp(peer_CN, common_name)){
		err_exit(FMT_CN_MISMATCH);
	}*/
	
	/* check server email */
	X509_NAME_get_text_by_NID(X509_get_subject_name(peer_cert), NID_pkcs9_emailAddress, peer_email, BUFFER_SIZE);
	/*if(strcasecmp(peer_email, server_email)){
		err_exit(FMT_EMAIL_MISMATCH);
	}*/
	
	printf(FMT_CLIENT_INFO, peer_CN, peer_email);
}

void read_write(SSL *ssl, char *answer, char *output){
	/* check certificate */
	check_certificate(ssl, COMMON_NAME, SERVER_EMAIL);
	
	int read_res = SSL_read(ssl, output, BUFFER_SIZE);
	
	if(read_res < 0){
		berr_exit("SSL read encountered problems");
	}
	
	output[read_res] = '\0';
	
	printf(FMT_OUTPUT, output, answer);
	
	int write_res = SSL_write(ssl, answer, strlen(answer));
	
	switch(SSL_get_error(ssl, write_res)) {
		case SSL_ERROR_NONE:
			if(strlen(answer) != write_res){
				err_exit("SSL write was not completed");
				break;
			}
		default:
			berr_exit("SSL write encountered error");
	}
}

int main(int argc, char **argv)
{
  int s, sock, port=PORT;
  struct sockaddr_in sin;
  int val=1;
  pid_t pid;

  SSL_CTX *ctx;
  SSL *ssl;
  BIO *sbio;
  
  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 2:
      port=atoi(argv[1]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s port\n", argv[0]);
      exit(0);
  }

  if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
    perror("socket");
    close(sock);
    exit(0);
  }
  
  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);
  
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));
    
  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
    perror("bind");
    close(sock);
    exit (0);
  }
  
  if(listen(sock,5)<0){
    perror("listen");
    close(sock);
    exit (0);
  } 

  ctx = initialize_ctx(SERVER_KEY, PASSWORD);
  SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
      NULL);
  
  while(1){
    
    if((s=accept(sock, NULL, 0))<0){
      perror("accept");
      close(sock);
      close(s);
      exit (0);
    }
    
    /*fork a child to handle the connection*/
    
    if((pid=fork())){
      close(s);
    }
    else {
      /*Child code*/
      int len;
      char buf[256];
      char *answer = "42";

      ssl = SSL_new(ctx);
      sbio = BIO_new_socket(s, BIO_NOCLOSE);
      SSL_set_bio(ssl, sbio, sbio);

      if (int r=SSL_accept(ssl) <= 0) {
        berr_exit(FMT_ACCEPT_ERR);
      }

      read_write(ssl, answer, buf);
      
      close(sock);
      close(s);
      return 0;
    }
  }
  
  close(sock);
  return 1;
}
