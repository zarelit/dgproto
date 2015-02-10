/**
 * David Costa <david.costa@ieee.org>, Giuliano Peraz <giuliano.peraz@gmail.com>
 */


/**
 * This is the client implementation for the D&G® Secure Protocol.
 * The client simply opens a socket to a server, of which has the public key, and then
 * start the protocol in order to establish a session key for sending something
 * through the unsecure channel.
 */

#include <sys/stat.h>
#include "common.h"
#include "protocol.h"
#include "utils.h"

//! How much of the file we work with at a time
#define CHUNK_SIZE 512

/**
 * Determine file size or quit
 */
ssize_t getfsize(FILE* fd);

int main (int argc, char** argv)
{
	/*
	 * Network related variables
	 */
	struct addrinfo query;
	struct addrinfo *servers;
	int servfd;

	/*
	 * File related variables
	 */
	FILE* file_to_send;
	ssize_t fsize;
	unsigned char ptextbuf[CHUNK_SIZE];

	/*
	 * Other variables
	 */
	int s; // exit status of some calls, used for error checking.

	/*
	 * Protocol related variables
	 */
	BIGNUM*	Na=NULL;
	BIGNUM*	Nb=NULL;
	uint8_t* IV=NULL;
	uint8_t* key=NULL;
	msg_data m1, m2, m3, m4;

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
	 * Step 1:
	 * Generate Nonce and send M1
	 */
	Na = generate_random_nonce();
	m1.data = create_m1(&(m1.data_len), 'A', Na);
	if( m1.data == NULL){
		fprintf(stderr, "Error generating M1");
		exit(EXIT_FAILURE);
	}
	s = sendbuf(servfd, m1.data, m1.data_len);
	if( s != 1){
		fprintf(stderr, "Error while sending M1");
		exit(EXIT_FAILURE);
	}

	/*
	 * Step 5:
	 * Send the file to the server
	 */
	// Get file size - used to show progress
	fsize = getfsize(file_to_send);

	printf("Sending the file to the server...\n");

	printf("File sent.\n");



	/*
	 * cleanup and quit
	 */
	close(servfd);
	fclose(file_to_send);
	return EXIT_SUCCESS;
}

ssize_t getfsize(FILE* fd){
	struct stat status;
	int x;
	x=fstat(fileno(fd), &status);
	if(x){
		perror("Cannot determine file size.");
		exit(EXIT_FAILURE);
	}

	return status.st_size;
}
