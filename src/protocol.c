/**
 * David Costa <david.costa@ieee.org>, Giuliano Peraz <giuliano.peraz@gmail.com>
 */

/**
 * This file contains all the implementation of the header protocol.h in the include directory
 * of this project. It is thought for simplifying the creation of the messages of the protocol.
 * This file must use OpenSSL and return ever a string that has to be freed after use.
 */

#include "../include/protocol.h"
#include "../include/utils.h"

uint8_t*
create_m1 (size_t* msg_len, aid_t id, BIGNUM* Na)
{
	// The whole message M1
    uint8_t* msg;

	// The public key of the server
	EVP_PKEY* skey;
	FILE* skeyfh;


	// Signing related variables
	unsigned char* sig; // actual signature
	size_t siglen; //length of the signature
	unsigned char* Na_value; // Bytes of Na in big-endian format
	size_t Na_size; // Length of Na in bytes


	// Encryption related variables
	EVP_PKEY_CTX* encctx;
	unsigned char* enc; // actual encrypted content
	size_t enclen; // length of the encrypted content

	// Load server key, called server.pem
	skeyfh = fopen("keys/server.pem","r");
	skey = PEM_read_PUBKEY(skeyfh, &skey, NULL, NULL);
	if(!skey){
		fprintf(stderr,"Cannot read server key from file keys/server.pem\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * Step 0: Convert Na in a signable buffer
	 */
	Na_size = BN_num_bytes(Na);
	Na_value = malloc(Na_size);
	BN_bn2bin(Na, Na_value);

	/*
	 * Step 1: Sign Na
	 */
	sig = sign("keys/client.pem", Na_value, Na_size, &siglen);

	/*
	 * Step 2: Encrypt the signed Na using the server public key
	 */
	// create encryption context
	encctx = EVP_PKEY_CTX_new(skey,NULL);
	if (!encctx){
		fprintf(stderr,"Cannot create an encryption context\n");
		exit(EXIT_FAILURE);
	}
	if (EVP_PKEY_encrypt_init(encctx) <= 0){
		fprintf(stderr,"Cannot create an encryption context\n");
		exit(EXIT_FAILURE);
	}

	/* Determine buffer length */
	if (EVP_PKEY_encrypt(encctx, NULL, &enclen, sig, siglen) <= 0)
		exit(EXIT_FAILURE);

	enc = malloc(enclen);
	if (!enc){
		fprintf(stderr,"Out of memory\n");
		exit(EXIT_FAILURE);
	}

	// Do the actual encryption
	if (EVP_PKEY_encrypt(encctx, enc, &enclen, sig, siglen) <= 0){
		fprintf(stderr,"Cannot sign nonce Na\n");
		exit(EXIT_FAILURE);
	}

	// the whole message is encrypted + 1 byte of the id
	*msg_len = enclen + sizeof(id);
	msg = malloc(*msg_len);

	// build the message, prepending the ID and copying the encrypted part.
	msg[0] = id;
	memcpy(&msg[1],enc,enclen);

	/*
	 * Cleanup
	 */
	free(sig);
	free(Na_value);
	free(enc);
    return msg;
}

uint8_t*
create_m2 (size_t* msg_len, aid_t id, BIGNUM* Nb, BIGNUM* Na, uint8_t** iv)
{
    uint8_t *msg; // The message this function is able to build
    uint8_t *enc_part, *tmp; // The encrypted part of the message
    uint8_t *signature, *Na_bin_val, *Nb_bin_val;
    size_t sig_len, enc_part_len, Nb_len, Na_len, iv_len;
    EVP_PKEY *cpub_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    FILE* cpub_key_file;

    // Get the public key of the client in order to encrypt some part of the message
    cpub_key_file = fopen("keys/client.pub.pem", "r");
    if (cpub_key_file == NULL)
    {
        perror("fopen");
        msg = NULL;
        *msg_len = 0;
        goto exit_create_m2;
    }
    cpub_key = PEM_read_PUBKEY(cpub_key_file, &cpub_key, NULL, NULL);
    if (cpub_key == NULL)
    {
        fprintf(stderr, "Error: can't read client public key\n");
        msg = NULL;
        *msg_len = 0;
        goto exit_create_m2;
    }
    // Translate nonces to a binary format
    Nb_bin_val = malloc(BN_num_bytes(Nb));
    Nb_len = BN_bn2bin(Nb, Nb_bin_val);
    Na_bin_val = malloc(BN_num_bytes(Na));
    Na_len = BN_bn2bin(Na, Na_bin_val);

    // Sign the binary value of Nb with the private key of the server
    signature = sign("keys/server.pem", Nb_bin_val, Nb_len, &sig_len);

    // Create the encrypted part of the message by concatenating Na, Nb and the signature
    enc_part_len = Na_len + Nb_len + sig_len;
    enc_part = malloc(enc_part_len);
    if (enc_part == NULL)
    {
        fprintf(stderr, "Out of Memory");
        msg = NULL;
        *msg_len = 0;
        goto cleanup_create_m2;
    }
    tmp = enc_part;
    memcpy(enc_part, Na_bin_val, Na_len);
    tmp += Na_len;
    memcpy(tmp, Nb_bin_val, Nb_len);
    tmp += Nb_len;
    memcpy(tmp, signature, sig_len);

    // Start encryption of the enc_part of m2
    ctx = EVP_PKEY_CTX_new(cpub_key, NULL);
    if (ctx == NULL)
    {
        fprintf(stderr, "Error allocating context for encrypting the message\n");
        msg = NULL;
        *msg_len = 0;
        goto cleanup_create_m2;
    }
    if (EVP_PKEY_encrypt(ctx, tmp, msg_len, enc_part, enc_part_len) <= 0)
    {
        fprintf(stderr, "Error during encryption\n");
        msg = NULL;
        *msg_len = 0;
        goto cleanup_create_m2;
    }
    // Create the random Initialization Vector
    *iv = generate_random_aes_iv(&iv_len);
    if (*iv == NULL)
    {
        fprintf(stderr, "Error generating the IV\n");
        msg = NULL;
        *msg_len = 0;
        goto cleanup_create_m2;
    }

    // Create the whole message by concatenating the clear text part and the encrypted one
    msg = malloc(sizeof(id) + iv_len + enc_part_len);
    if (msg == NULL)
    {
        fprintf(stderr, "Error allocating message\n");
        msg = NULL;
        *msg_len = 0;
        goto cleanup_create_m2;
    }
    tmp = msg;
    memcpy(msg, (void *)&id, sizeof(id));
    tmp += sizeof(id);
    memcpy(tmp, *iv, iv_len);
    tmp += iv_len;
    memcpy(tmp, enc_part, enc_part_len);

    // Clean up
    EVP_PKEY_CTX_free(ctx);

cleanup_create_m2:
    fclose(cpub_key_file);
    free(enc_part);
    free(Nb_bin_val);
    free(Na_bin_val);
    free(signature);
exit_create_m2:
    return msg;
}

uint8_t*
create_m3 (size_t* msg_len, BIGNUM* key, BIGNUM* Nb, uint8_t* iv)
{
    uint8_t* msg = NULL;
    return msg;
}

uint8_t*
create_m4 (size_t* msg_len, uint8_t* key, BIGNUM* Na, uint8_t* iv)
{
    uint8_t *encr_msg = NULL;
    uint8_t *Na_bin_val;
    size_t Na_len;

    Na_bin_val = malloc(BN_num_bytes(Na));
    Na_len = BN_bn2bin(Na, Na_bin_val);
    encr_msg = do_aes256_crypt(Na_bin_val, key, iv, &Na_len);
    if (encr_msg == NULL)
    {
        fprintf(stderr, "Error crypting the message m3\n");
        *msg_len = 0;
    }
    else
    {
        // Na_len is now storing the real size of the encrypted message
        *msg_len = Na_len;
    }
    free(Na_bin_val);
    return encr_msg;
}

BIGNUM*
generate_random_nonce (void){
	BIGNUM* nonce = BN_new();
	int x;

	if(!nonce){
		fprintf(stderr,"Out of memory\n");
		exit(EXIT_FAILURE);
	}

	x=BN_rand(nonce, 128, 0, 0);
	if(!x){
		fprintf(stderr,"Cannot generate a random nonce\n");
		exit(EXIT_FAILURE);
	}

	return nonce;
}

uint8_t*
generate_key (BIGNUM *Na, BIGNUM *Nb)
{
    uint8_t *key, *tmp;
    uint8_t *Na_bin_val = NULL, *Nb_bin_val = NULL;
    size_t Na_len, Nb_len, tmp_len;

    // Create the "message" to be hashed by SHA256 algorithm
    Na_len = BN_bn2bin(Na, Na_bin_val);
    Nb_len = BN_bn2bin(Nb, Nb_bin_val);
    tmp_len = Na_len + Nb_len + SALT_SIZE;
    tmp = malloc(tmp_len);
    if (tmp == NULL)
    {
        fprintf(stderr, "Error allocating memory for the key\n");
        key = NULL;
        goto exit_generate_key;
    }
    key = tmp;
    memcpy((void*) key, (void *) Na_bin_val, Na_len);
    tmp += Na_len;
    memcpy((void*) tmp, (void *) Nb_bin_val, Nb_len);
    tmp += Nb_len;
    memcpy((void*) tmp, (void *) SALT, SALT_SIZE);
    tmp = key;

    // Get the hash of the temporary "message"
    key = do_sha256_digest(tmp, tmp_len);
    free(tmp);
    if (key == NULL)
    {
        fprintf(stderr, "Error creating the key\n");
    }

exit_generate_key:
    free(tmp);
    return key;
}

int
verifymessage_m1 (uint8_t *msg, size_t *msg_len)
{
    int ret_val = 0;

    BIGNUM* Na;
    /* A,{Na, sign(Na)} */

    return ret_val;
}

int
verifymessage_m2 (uint8_t *msg, size_t *msg_len, BIGNUM *Na)
{
    return 0;
}

int
verifymessage_m3 (uint8_t *msg, size_t *msg_len, BIGNUM *Nb, uint8_t *key)
{
    return 0;
}

int
verifymessage_m4 (uint8_t *msg, size_t *msg_len, BIGNUM *Na, uint8_t *key)
{
    return 0;
}
