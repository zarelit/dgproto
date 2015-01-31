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
do_aes256_crypt (uint8_t* msg, uint8_t* key, uint8_t* iv, size_t* msg_len)
{
    EVP_CIPHER_CTX *ctx;
    uint8_t *encr_msg;
    size_t enc_len; // Encypted message length and block size of the cipher
    const size_t bsize = EVP_CIPHER_block_size(EVP_aes_256_cbc());

    if (iv == NULL || msg == NULL || key == NULL || *msg_len <= 0)
    {
        fprintf(stderr, "Error: invalid argument passed");
        encr_msg = NULL;
        *msg_len = 0;
        goto exit_do_aes256_crypt;
    }

    // Finally do the encryption
    encr_msg = malloc(*msg_len + bsize);
    ctx = malloc(sizeof(EVP_CIPHER_CTX));
    EVP_CIPHER_CTX_init(ctx);
    if (EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key, iv) == 0)
    {
        fprintf(stderr, "Error initializing the encryption\n");
        free(encr_msg);
        *msg_len = 0;
        goto exit_do_aes256_crypt;
    }
    enc_len = 0;
    if (EVP_EncryptUpdate(ctx, encr_msg, (int *) &enc_len, msg, *msg_len) == 0)
    {
        fprintf(stderr, "Error during the encryption\n");
        free(encr_msg);
        *msg_len = 0;
        goto exit_do_aes256_crypt;
    }
    if (EVP_EncryptFinal(ctx, encr_msg + enc_len, (int *)msg_len) == 0)
    {
        fprintf(stderr, "Error finalizing the encryption\n");
        free(encr_msg);
        *msg_len = 0;
        goto exit_do_aes256_crypt;
    }
    *msg_len = enc_len;
exit_do_aes256_crypt:
    EVP_CIPHER_CTX_cleanup(ctx);
    free(ctx);
    return encr_msg;
}

uint8_t*
do_aes256_decrypt (uint8_t* enc_msg, uint8_t* key, uint8_t* iv, size_t* msg_len)
{
    EVP_CIPHER_CTX *ctx;
    uint8_t *dec_msg;
    size_t dec_len; // Encypted message length and block size of the cipher
    const size_t bsize = EVP_CIPHER_block_size(EVP_aes_256_cbc());

    if (iv == NULL || enc_msg == NULL || key == NULL || *msg_len < 0)
    {
        fprintf(stderr, "Error: invalid argument passed\n");
        dec_msg = NULL;
        *msg_len = 0;
        goto exit_do_aes256_decrypt;
    }

    // Finally do the encryption
    dec_msg = malloc(*msg_len + bsize);
    ctx = malloc(sizeof(EVP_CIPHER_CTX));
    EVP_CIPHER_CTX_init(ctx);
    if (EVP_DecryptInit(ctx, EVP_aes_256_cbc(), key, iv) == 0)
    {
        fprintf(stderr, "Error initializing the decryption\n");
        free(dec_msg);
        *msg_len = 0;
        goto exit_do_aes256_decrypt;
    }
    dec_len = 0;
    if (EVP_DecryptUpdate(ctx, enc_msg, (int *)&dec_len, dec_msg, *msg_len) == 0)
    {
        fprintf(stderr, "Error during the decryption\n");
        free(enc_msg);
        *msg_len = 0;
        goto exit_do_aes256_decrypt;
    }
    if (EVP_DecryptFinal(ctx, dec_msg + dec_len, (int *)msg_len) == 0)
    {
        fprintf(stderr, "Error finalizing the decryption\n");
        free(enc_msg);
        *msg_len = 0;
        goto exit_do_aes256_decrypt;
    }
    *msg_len = dec_len;
    exit_do_aes256_decrypt:
    EVP_CIPHER_CTX_cleanup(ctx);
    free(ctx);
    return dec_msg;
}

uint8_t* sign(const char* keypath, const uint8_t* payload, const size_t plen, size_t* slen){

	FILE* ckeyfh;
	EVP_PKEY* ckey=NULL;
	EVP_PKEY_CTX* sigctx;
	uint8_t *sig;
	size_t siglen;

	// Load signing key
	ckeyfh = fopen(keypath,"r");
	if(!ckeyfh) exit(EXIT_FAILURE);
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

	EVP_PKEY_CTX_free(sigctx);
	return sig;
}

int verify(const char* keypath, BIGNUM* nonce, const uint8_t* sig, size_t slen){
	// Nonce
	uint8_t* N;
	size_t Nlen;

	// Context and key
	EVP_PKEY_CTX *verctx;
	FILE* vkeyfh;
	EVP_PKEY *vkey=NULL;

	// Return codes and errors
	int ret;
	unsigned long vererr;

	/*
	 * Open the public key of the client for verification
	 */
	vkeyfh = fopen(keypath,"r");
	if(!vkeyfh) exit(EXIT_FAILURE);
	vkey = PEM_read_PUBKEY(vkeyfh, &vkey, NULL, NULL);
	if(!vkey){
		fprintf(stderr,"Cannot read verification key from file %s\n", keypath);
		exit(EXIT_FAILURE);
	}

	verctx = EVP_PKEY_CTX_new(vkey, NULL);
	if (!verctx){
		fprintf(stderr,"Cannot create a verify context\n");
		exit(EXIT_FAILURE);
	}

	if (EVP_PKEY_verify_init(verctx) <= 0){
		fprintf(stderr,"Cannot create a verify context\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * Convert the nonce in a string so that it can be verified
	 */
	N = malloc(BN_num_bytes(nonce));
	Nlen = BN_bn2bin(nonce, N);

	/* Perform actual verify operation */
	ret = EVP_PKEY_verify(verctx, sig, slen, N, Nlen);
	if( ret != 1 ){
		vererr = ERR_get_error();
		fprintf(stderr,"The verify operation on the nonce has failed with code %lu. RET=%d\n",vererr,ret);
	}

	free(N);
	EVP_PKEY_CTX_free(verctx);
	return (ret==1)?1:0;
}

uint8_t*
generate_random_aes_iv (size_t *iv_len)
{
    uint8_t *buffer, buf_len, i;

    buf_len = EVP_CIPHER_iv_length(EVP_aes_256_cbc());
    buffer = malloc(buf_len);
    if (buffer == NULL)
    {
        fprintf(stderr, "Error: out of memory\n");
        buffer = NULL;
        *iv_len = 0;
        goto exit_generate_random_aes_iv;
    }
    // Fill the buffer with random content
    srand(time(NULL));
    for (i = 0; i < buf_len; i ++)
    {
        buffer[i] = (uint8_t) random();
    }

    // Generate the criptographically strong IV (according to OPENSSL)
    if (RAND_bytes(buffer, buf_len) < 1)
    {
        fprintf(stderr, "Error generating criptographically strong random number\n");
        free(buffer);
        *iv_len = 0;
    }
    *iv_len = buf_len;
exit_generate_random_aes_iv:
    return buffer;
}

uint8_t*
do_sha256_digest (uint8_t* msg, size_t msg_len)
{
    uint8_t *dig;
    size_t dig_len;
    EVP_MD_CTX *ctx;

    dig = malloc(EVP_MD_size(EVP_sha256()));
    if (dig == NULL)
    {
        fprintf(stderr, "Error allocating memory for the digest\n");
        goto exit_do_sha256_digest;
    }

    // Do the hashing of the msg
    ctx = EVP_MD_CTX_create();
    if (EVP_DigestInit(ctx, EVP_sha256()) != 1)
    {
        fprintf(stderr, "Error initializing digest algorithm\n");
        free(dig);
        goto cleanup_do_sha256_digest;
    }
    if (EVP_DigestUpdate(ctx, msg, msg_len) != 1)
    {
        fprintf(stderr, "Error during the hashing of the message\n");
        free(dig);
        goto cleanup_do_sha256_digest;
    }
    if (EVP_DigestFinal(ctx, dig, (unsigned int*) &dig_len) != 1)
    {
        fprintf(stderr, "Error finalizing the digest\n");
        free(dig);
        goto cleanup_do_sha256_digest;
    }

    // Check if the size is correct
    if (dig_len != EVP_MD_size(EVP_sha256()))
    {
        fprintf(stderr, "Error, the digest's length is less than expected\n");
        free(dig);
    }

cleanup_do_sha256_digest:
    EVP_MD_CTX_cleanup(ctx);
    free(ctx);
exit_do_sha256_digest:
    return dig;
}
