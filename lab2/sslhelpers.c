#include "sslhelpers.h"

BIO *bio_err = 0;
static char *pass;

int err_exit(char* string) {
	fprintf(stderr,"%s\n",string);
	exit(0);
}

int berr_exit(char *string){
    BIO_printf(bio_err,"%s\n",string);
    ERR_print_errors(bio_err);
    exit(0);
}

int pem_passwd_cb(char *buf, int size, int rwflag, void *password){
	strncpy(buf, (char *)(password), size);
	buf[size - 1] = '\0';
	return(strlen(buf));
}

SSL_CTX *initialize_ctx(char *keyfile, char *password){
	SSL_METHOD *meth;
	SSL_CTX *ctx;

	if (!bio_err) {
		SSL_library_init();
		SSL_load_error_strings();

      	/* An error write context */
      	bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
	}


    //Ignore sigpipe, using tcp
    signal(SIGPIPE,SIG_IGN);

   	meth=SSLv23_method();
   	ctx=SSL_CTX_new(meth);

   	if(!(SSL_CTX_use_certificate_chain_file(ctx, keyfile)))
   		berr_exit("Can’t read certificate file");

	SSL_CTX_set_default_passwd_cb(ctx, pem_passwd_cb);

	if(!(SSL_CTX_use_PrivateKey_file(ctx, keyfile,SSL_FILETYPE_PEM)))
		berr_exit("Can’t read key file");

	/* Load the CAs we trust*/
   	if(!(SSL_CTX_load_verify_locations(ctx, CA_LIST,0)))
   		berr_exit("Can't read CA list");
   	return ctx;
}

void destroy_ctx(SSL_CTX *ctx) {
	SSL_CTX_free(ctx);
}