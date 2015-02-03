/**
 * David Costa <david.costa@ieee.org>, Giuliano Peraz <giuliano.peraz@gmail.com>
 */

#include "../include/utils.h"
#include "../include/common.h"

uint8_t*
conc_msgs (size_t* buf_len, size_t argc, ...)
{
    va_list msgs;
    msg_data msg;
    uint8_t *buffer, *tmp;
    size_t el_cnt; // ELement CouNTer

    // Input error checking
    if (buf_len == NULL || argc == 0)
    {
        buffer = NULL;
        fprintf(stderr, "Invalid argument\n");
        goto exit_conc_msgs;
    }

    // Compute the total number of bytes the buffer has to have
    *buf_len = 0;
    va_start(msgs, argc);
    for (el_cnt = 0; el_cnt < argc; el_cnt ++)
    {
        msg = va_arg(msgs, msg_data);
        if (msg.data == NULL || msg.data_len == 0)
        {
            buffer = NULL;
            *buf_len = 0;
            fprintf(stderr, "Element number %d of the list is not correct\n",(int) el_cnt);
            goto exit_conc_msgs;
        }
        *buf_len += msg.data_len;
    }
    va_end(msgs);

    // Copy the data into the buffer
    buffer = malloc(sizeof(uint8_t) * (*buf_len));
    if (buffer == NULL)
    {
        fprintf(stderr, "Out of memory\n");
        goto exit_conc_msgs;
    }
    tmp = buffer;
    va_start(msgs, argc);
    for (el_cnt = 0; el_cnt < argc; el_cnt ++)
    {
        msg = va_arg(msgs, msg_data);
        memcpy(tmp, msg.data, msg.data_len);
        tmp += msg.data_len;
    }
    va_end(msgs);

exit_conc_msgs:
    return buffer;
}

uint8_t
extr_msgs (uint8_t* buffer, size_t argc, ...)
{
    va_list msgs;
    uint8_t ret_val = 0;
    uint8_t *data_p; // Data pointer
    size_t el_cnt;   // ELement CouNTer
    msg_data *msg;

    // Input error checking
    if (argc == 0)
    {
        fprintf(stderr, "Parameter argc is 0\n");
        goto exit_extr_msgs;
    }

    // Extract the messages of the buffer
    va_start(msgs, argc);
    data_p = buffer;
    for (el_cnt = 0; el_cnt < argc; el_cnt ++)
    {
        msg = va_arg(msgs, msg_data*);
        if (msg == NULL)
        {
            fprintf(stderr, "Pointer number %d of the list is NULL\n", (int) el_cnt);
            break;
        }
        if (msg -> data_len == 0)
        {
            fprintf(stderr, "Data len of the element number %d of the list is 0\n", (int) el_cnt);
            break;
        }
        msg -> data = malloc(sizeof(uint8_t) * msg -> data_len);
        memcpy(msg -> data, data_p, msg -> data_len);
        data_p += msg -> data_len;
    }
    va_end(msgs);
    ret_val = 1;

exit_extr_msgs:
    return ret_val;
}

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
	if (EVP_PKEY_sign(sigctx, sig, slen, payload, plen) <= 0){
		ERR_load_crypto_strings();
		fprintf(stderr,"Signing operation failed\n");
		printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
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

uint8_t* encrypt(const char* keypath, const uint8_t* p, const size_t plen, size_t* clen){
	// Context and key
	EVP_PKEY_CTX *encctx;
	FILE* ckeyfh;
	EVP_PKEY *ckey=NULL;

	// Return codes and errors
	int ret;
	unsigned long encerr;

	/* The buffer with the ciphertext */
	uint8_t* c;

	/*
	 * Open a public key for encryption
	 */
	ckeyfh = fopen(keypath,"r");
	if(!ckeyfh) exit(EXIT_FAILURE);
	ckey = PEM_read_PUBKEY(ckeyfh, &ckey, NULL, NULL);
	if(!ckey){
		fprintf(stderr,"Cannot read encryption key from file %s\n", keypath);
		exit(EXIT_FAILURE);
	}

	encctx = EVP_PKEY_CTX_new(ckey, NULL);
	if (!encctx){
		fprintf(stderr,"Cannot create an encryption context\n");
		exit(EXIT_FAILURE);
	}

	if (EVP_PKEY_encrypt_init(encctx) <= 0){
		fprintf(stderr,"Cannot create an encryption context\n");
		exit(EXIT_FAILURE);
	}

	/* Determine how long is the ciphertext buffer */
	if (EVP_PKEY_encrypt(encctx, NULL, clen, p, plen) <= 0)
		exit(EXIT_FAILURE);

	c = malloc(*clen);
	if(!c){
		fprintf(stderr,"Out of memory\n");
		exit(EXIT_FAILURE);
	}

	/* Perform actual encryption */
	ret = EVP_PKEY_encrypt(encctx, c, clen, p, plen);
	if( ret != 1 ){
		encerr = ERR_get_error();
		fprintf(stderr,"The encryption has failed with code %lu. RET=%d\n",encerr,ret);
	}

	EVP_PKEY_CTX_free(encctx);
	return c;
}


uint8_t* decrypt(const char* keypath, const uint8_t* c, const size_t clen, size_t* plen){
	// Context and key
	EVP_PKEY_CTX *decctx;
	FILE* dkeyfh;
	EVP_PKEY *dkey=NULL;

	// Return codes and errors
	int ret;
	unsigned long decerr;

	/* The buffer with the plaintext */
	uint8_t* p;

	/*
	 * Open a public key for decryption
	 */
	dkeyfh = fopen(keypath,"r");
	if(!dkeyfh) exit(EXIT_FAILURE);
	dkey = PEM_read_PrivateKey(dkeyfh, &dkey, NULL, NULL);
	if(!dkey){
		fprintf(stderr,"Cannot read decryption key from file %s\n", keypath);
		exit(EXIT_FAILURE);
	}

	decctx = EVP_PKEY_CTX_new(dkey, NULL);
	if (!decctx){
		fprintf(stderr,"Cannot create an decryption context\n");
		exit(EXIT_FAILURE);
	}

	if (EVP_PKEY_decrypt_init(decctx) <= 0){
		fprintf(stderr,"Cannot create an decryption context\n");
		exit(EXIT_FAILURE);
	}

	/* Determine how long is the ciphertext buffer */
	if (EVP_PKEY_decrypt(decctx, NULL, plen, c, clen) <= 0)
		exit(EXIT_FAILURE);

	p = malloc(*plen);
	if(!p){
		fprintf(stderr,"Out of memory\n");
		exit(EXIT_FAILURE);
	}

	/* Perform actual decryption */
	ret = EVP_PKEY_decrypt(decctx, p, plen, c, clen);
	if( ret != 1 ){
		decerr = ERR_get_error();
		fprintf(stderr,"The decryption has failed with code %lu. RET=%d\n",decerr,ret);
	}

	EVP_PKEY_CTX_free(decctx);
	return p;
}
