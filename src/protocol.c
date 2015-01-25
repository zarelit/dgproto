/**
 * David Costa <david.costa@ieee.org>, Giuliano Peraz <giuliano.peraz@gmail.com>
 */

/**
 * This file contains all the implementation of the header protocol.h in the include directory
 * of this project. It is thought for simplifying the creation of the messages of the protocol.
 * This file must use OpenSSL and return ever a string that has to be freed after use.
 */

#include "../include/protocol.h"

uint8_t* create_m1 (uint64_t *msg_len, uint8_t id, BIGNUM* Na)
{
    uint8_t* msg;

    return msg;
}

uint8_t* create_m2 (uint64_t *msg_len, uint8_t id, BIGNUM* Nb)
{
    uint8_t* msg;

    return msg;
}

uint8_t* create_m3 (uint64_t *msg_len, BIGNUM* key, BIGNUM* Nb)
{
    uint8_t* msg;

    return msg;
}

uint8_t* create_m4 (uint64_t *msg_len, BIGNUM* key, BIGNUM* Nb)
{
    uint8_t* msg;

    return msg;
}

BIGNUM *generate_random_nonce (void){
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
