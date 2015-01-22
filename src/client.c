/**
 * David Costa <david.costa@ieee.org>, Giuliano Peraz <giuliano.peraz@gmail.com>
 */


/**
 * This is the client implementation for the D&G® Secure Protocol.
 * The client simply opens a socket to a server, of which has the public key, and then
 * start the protocol in order to establish a session key for sending something
 * through the unsecure channel.
 */

#include "../include/common.h"
#include <string.h>


int main (int argc, char** argv)
{
	struct addrinfo query;
	struct addrinfo *servers;

	int s; // exit status of some calls, used for error checking.

	if(argc != 3){
		printf("Usage: %s <Server IPv4> <file to send>\n",argv[0]);
		exit(EXIT_FAILURE);
	}

	/*
	 * Obtain a valid address for server or quit
	 */
	memset(&query, 0, sizeof query);	// Erase unneeded fields
	query.ai_family = AF_INET;			// IPv4 only
	query.ai_socktype = SOCK_STREAM;	// Protocol runs on TCP

	s = getaddrinfo(argv[1], SRV_PORT, &query, &servers);
	if(s){
		fprintf(stderr,"Cannot connect to server: %s\n",gai_strerror(s));
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}
