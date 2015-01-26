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

	// The private key of the client
	EVP_PKEY* ckey;
	FILE* ckeyfh;
	// The public key of the server
	EVP_PKEY* skey;
	FILE* skeyfh;


	// Load client key, called client.pem
	ckeyfh = fopen("keys/client.pem","r");
	ckey = PEM_read_PrivateKey(ckeyfh, &ckey, NULL, NULL);
	if(!ckey){
		fprintf(stderr,"Cannot read client key from file %s\n");
		exit(EXIT_FAILURE);
	}

	// Load server key, called server.pem
	skeyfh = fopen("keys/server.pem","r");
	skey = PEM_read_PUBKEY(skeyfh, &skey, NULL, NULL);
	if(!skey){
		fprintf(stderr,"Cannot read server key from file %s\n");
		exit(EXIT_FAILURE);
	}


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
