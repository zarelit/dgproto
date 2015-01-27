/**
 * David Costa <david.costa@ieee.org>, Giuliano Peraz <giuliano.peraz@gmail.com>
 */

#include "../include/utils.h"
#include "../include/common.h"

void sendbuf(int sock, unsigned char* buf, ssize_t len){
	ssize_t sent=0;
	ssize_t n=0;

	while(sent != len){
		// Always try to send the whole buffer
		n = send(sock, &buf[sent], len - sent, 0);

		// Check for errors or update the index of what has already been sent
		if(n != -1){
			sent += n;
		} else{
			perror("Cannot send data to server");
			exit(EXIT_FAILURE);
		}
	}
}

void hexdump(FILE *fh, unsigned char* buf, size_t buflen){
	int i;

	for(i=0; i<buflen; i++){
		fprintf(fh,"%02hhX",buf[i]);
	}
}

/**
 * This function reads the Initialization Vector (IV) from the file path passed by parameter.
 * \param iv_file the Initialization Vector for the cipher.
 * \returns a buffer that contains the IV or NULL if an error has occourred.
 */
uint8_t*
read_iv_from_file (FILE* iv_file)
{
    uint8_t *iv_buf;
    size_t byte_read;

    iv_buf = malloc(EVP_MAX_IV_LENGTH);
    byte_read = fread((void*) iv_buf, sizeof(uint8_t), EVP_MAX_IV_LENGTH, iv_file);
    if(byte_read < EVP_MAX_IV_LENGTH * sizeof(uint8_t))
    {
        fprintf(stderr, "Can't read the whole IV\n");
        if(feof(iv_file) > 0)
        {
            fprintf(stderr, "EOF reached before expected\n");
        }
        else if (ferror > 0)
        {
            fprintf(stderr, "Error reading the file\n");
        }
        free(iv_buf);
    }
    return iv_buf;
}

uint8_t*
do_aes256_crypt (uint8_t* msg, uint8_t* key, uint64_t* msg_len)
{
    EVP_CIPHER_CTX *ctx;
    uint8_t *encr_msg;
    size_t enc_len, bsize; // Encypted message length and block size of the cipher

    EVP_CIPHER_CTX_Init(ctx);
}

uint8_t*
do_aes256_decrypt (uint8_t* msg, uint8_t* key, uint64_t* msg_len)
{

}

uint8_t* sign(const char* keypath, const uint8_t* payload, const size_t plen, size_t* slen){

	FILE* ckeyfh;
	EVP_PKEY* ckey;
	EVP_PKEY_CTX* sigctx; 
	uint8_t *sig;
	size_t siglen;

	// Load signing key
	ckeyfh = fopen(keypath,"r");
	ckey = PEM_read_PrivateKey(ckeyfh, &ckey, NULL, NULL);
	if(!ckey){
		fprintf(stderr,"Cannot read signing key from file %s\n", keypath);
		exit(EXIT_FAILURE);
	}

	// create signing context 
	sigctx = EVP_PKEY_CTX_new(ckey, NULL);
	if (!sigctx){
		fprintf(stderr,"Cannot create a signing context\n");
		exit(EXIT_FAILURE);
	}
	if (EVP_PKEY_sign_init(sigctx) <= 0){
		fprintf(stderr,"Cannot create a signing context\n");
		exit(EXIT_FAILURE);
	}

	// Ask the maximum signature size that will result in signing the payload
	if (EVP_PKEY_sign(sigctx, NULL, slen, payload, plen ) <= 0)
		exit(EXIT_FAILURE);

	sig = malloc(*slen);
	if(!sig){
		fprintf(stderr,"Out of memory\n");
		exit(EXIT_FAILURE);
	}

	// Do the real signature
	if (EVP_PKEY_sign(sigctx, sig, &siglen, payload, plen) <= 0){
		fprintf(stderr,"Signing operation failed\n");
		exit(EXIT_FAILURE);
	}

	return sig;
}
