/**
 * David Costa <david.costa@ieee.org>, Giuliano Peraz <giuliano.peraz@gmail.com>
 */

#include <openssl/evp.h>
#include <openssl/bn.h> // Big NUMs
#include <string.h>
#include <stdint.h>

/**
 * This function permits to create in one single shot the first message of the D&G protocol.
 * The first message simply contains a cleartext identifier of who wants to start the protocol and
 * a signed and crypted nounce called N_a.
 * \param msg_len the length of the resulting message after it has been produced by the function.
 * The value pointed by this pointer will be modified by the function itself.
 * \param id identifier of whom wants to start the communication with the server or another client.
 * This parameter is implementation dependent, in the sense we use only a byte for each actor
 * because we don't need more space to verify the protocol is working.
 * \param Na a pointer to a Big Num this function will modify to. This is the random nonce of 128
 * bit described in the protocol report.
 * \returns a byte string that contains the message ready to be sent.
 */
uint8_t* create_m1 (uint64_t *msg_len, uint8_t id, BIGNUM** Na);

/**
 * This function permits to create in one single shot the second message of the D&G protocol.
 * The second message contains an identifier, typically the server, and a crypted part that contains
 * N_a (see create_m1) and N_b, the signed nonce being created by the server.
 * \param msg_len the length of the resulting message after it has been produced by the function.
 * The value pointed by this pointer will be modified by the function itself.
 * \param id identifier of whom wants to  the communication with the client or another client.
 * This parameter is implementation dependent, in the sense we use only a byte for each actor
 * because we don't need more space to verify the protocol is working.
 * \param Nb a pointer to a Big Num this function will modify. This is the random nonce of 128
 * bit described in the protocol report.
 * \returns a byte string that contains the message ready to be sent.
 */
uint8_t* create_m2 (uint64_t *msg_len, uint8_t id, BIGNUM** Nb);

/**
 * This function permits to create in one single shot the third message of the D&G protocol.
 * The third message contains the hash of the Nb nonce crypted with the session key K. For more
 * information please refer to the protocol report.
 * \param key the session key for encrypting the message.
 * \param msg_len the length of the message this function has built.
 * \param Nb the nonce to be hashed and crypted.
 * \returns a byte string that contains the message ready to be sent.
 */
uint8_t* create_m3 (uint64_t *msg_len, BIGNUM* key, BIGNUM** Nb);

/**
 * This function permits to create in one single shot the fourth message of the D&G protocol.
 * The third message contains the hash of the Na nonce crypted with the session key K. For more
 * information please refer to the protocol report.
 * \param key the session key for encrypting the message.
 * \param msg_len the length of the message this function has built.
 * \param Na the nonce to be hashed and crypted.
 * \returns a byte string that contains the message ready to be sent.
 */
uint8_t* create_m4 (uint64_t *msg_len, BIGNUM* key, BIGNUM** Na);