/**
 * David Costa <david.costa@ieee.org>, Giuliano Peraz <giuliano.peraz@gmail.com>
 */

#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <arpa/inet.h>  // For hton* and ntoh* byte conversion functions,
                        // inet_pton, inet_ntop,
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <unistd.h>

#define SRV_PORT "1096"
#define SRV_MAX_CONN 20

/*
 * Keys' paths
 */
#define KEYS_DIR "keys/"
#define CLIENT_KEY KEYS_DIR "client.pem"
#define CLIENT_PUBKEY KEYS_DIR "client.pub.pem"
#define SERVER_KEY KEYS_DIR "server.pem"
#define SERVER_PUBKEY KEYS_DIR "server.pub.pem"

/**
 * Dimension of the buffer. Default is 1024 Bytes
 */
#define BUF_DIM 1024
