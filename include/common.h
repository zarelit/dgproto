/**
 * David Costa <david.costa@ieee.org>, Giuliano Peraz <giuliano.peraz@gmail.com>
 */

#include <stdio.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <arpa/inet.h> // For hton* and ntoh* byte conversion functions
#include <netinet/in.h>
#include <openssl/evp.h>