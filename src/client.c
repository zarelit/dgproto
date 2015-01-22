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


int main (int argc, char** argv)
{
	if(argc != 3){
		printf("Usage: %s <Server IPv4> <file to send>\n",argv[0]);
		exit(EXIT_FAILURE);
	}
	return 0;
}
