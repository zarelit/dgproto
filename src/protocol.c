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
create_m1 (uint64_t *msg_len, uint8_t id, BIGNUM* Na)
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
create_m2 (uint64_t *msg_len, uint8_t id, BIGNUM* Nb)
{
    uint8_t* msg;

    return msg;
}

uint8_t*
create_m3 (uint64_t *msg_len, BIGNUM* key, BIGNUM* Nb)
{
    uint8_t* msg;

    return msg;
}

uint8_t*
create_m4 (uint64_t *msg_len, uint8_t* key, BIGNUM* Nb)
{
    uint8_t* msg;

    return msg;
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

uint8_t
*generate_key (BIGNUM *Na, BIGNUM *Nb)
{
    return NULL;
}

int
verifymessage_m1 (uint8_t *msg)
{
    return 0;
}

int
verifymessage_m2 (uint8_t *msg, BIGNUM *Na)
{
    return 0;
}

int
verifymessage_m3 (uint8_t *msg, BIGNUM *Nb, uint8_t *key)
{
    return 0;
}

int
verifymessage_m4 (uint8_t *msg, BIGNUM *Na, uint8_t *key)
{
    return 0;
}
