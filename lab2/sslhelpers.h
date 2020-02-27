#ifndef _sslhelpers_h
#define _sslhelpers_h


#include <openssl/ssl.h>
#define CA_LIST "568ca.pem"
#define HOST	"localhost"


extern BIO *bio_err;
SSL_CTX *initialize_ctx(char *keyfile, char *password);

#endif