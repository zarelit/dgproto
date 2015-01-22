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

/**
 * Wrapper around send() that manages partial transmissions
 *
 * \param sock an already connected TCP socket
 * \param buf pointer to the data
 * \param len length of the data to be sent in bytes
 */
void sendbuf(int sock, void* buf, ssize_t len);

int main (int argc, char** argv)
{
	struct addrinfo query;
	struct addrinfo *servers;
	int servfd;

	FILE* file_to_send;

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

	/*
	 * Verify existence and readability of the file we have to send
	 */
	file_to_send = fopen(argv[2],"r");
	if(!file_to_send){
		perror("Cannot open the file to send");
		exit(EXIT_FAILURE);
	}

	/*
	 * Step 0:
	 * Open a TCP connection with the server.
	 */
	printf("About to connect to server\n");
	servfd = socket(servers->ai_family, servers->ai_socktype, servers->ai_protocol);
	if(servfd == -1){
		perror("Cannot create socket");
		exit(EXIT_FAILURE);
	}

	s = connect(servfd,servers->ai_addr, servers->ai_addrlen);
	if(s){
		perror("Cannot connect to server");
		exit(EXIT_FAILURE);
	}
	printf("Connection to server opened\n");

	/*
	 * cleanup and quit
	 */
	fclose(file_to_send);
	return EXIT_SUCCESS;
}

void sendbuf(int sock, void* buf, ssize_t len){
	ssize_t sent=0;
	ssize_t n=0;

	while(sent != len){
		// Always try to send the whole buffer
		n = send(sock, buf[sent], len - sent);

		// Check for errors or update the index of what has already been sent
		if(n != -1){
			sent += n;
		} else{
			perror("Cannot send data to server");
			exit(EXIT_FAILURE);
		}
	}
}
