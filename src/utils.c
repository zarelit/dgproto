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

uint8_t*
do_aes256_crypt (uint8_t* msg, uint8_t* key, uint64_t* msg_len)
{
    
}

uint8_t*
do_aes256_decrypt (uint8_t* msg, uint8_t* key, uint64_t* msg_len)
{

}