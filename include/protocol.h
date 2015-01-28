/**
 * David Costa <david.costa@ieee.org>, Giuliano Peraz <giuliano.peraz@gmail.com>
 */

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bn.h> // Big NUMs
#include <string.h>
#include <stdint.h>

/**
 * Salt being used into the key generation algorithm
 */
#define SALT "FzHp3CbMao"

/**
 * Length of the key in bit.
 */
#define KEY_LEN 256

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
uint8_t* create_m1 (size_t *msg_len, uint8_t id, BIGNUM* Na);

/**
 * This function permits to create in one single shot the second message of the D&G protocol.
 * The second message contains an identifier, typically the server, and a crypted part that contains
 * N_a (see create_m1) and N_b, the signed nonce being created by the server.
 * The message will be created with the following structure:
 *                      ID_SERVER || IV || encrypt(Na || Nb || sign(Nb), e_client)
 * where IV is the initialization vector for the cipher, e_client is the public key of the client.
 * \param msg_len the length of the resulting message after it has been produced by the function.
 * The value pointed by this pointer will be modified by the function itself.
 * \param id identifier of whom wants to  the communication with the client or another client.
 * This parameter is implementation dependent, in the sense we use only a byte for each actor
 * because we don't need more space to verify the protocol is working.
 * \param Nb a pointer to the server-side generated nonce.
 * \param Na a pointer to the client generated nonce.
 * \returns a byte string that contains the message ready to be sent or NULL if an error occours.
 */
uint8_t* create_m2 (size_t *msg_len, uint8_t id, BIGNUM* Nb, BIGNUM* Na);

/**
 * This function permits to create in one single shot the third message of the D&G protocol.
 * The third message contains the hash of the Nb nonce crypted with the session key K. For more
 * information please refer to the protocol report.
 * \param key the session key for encrypting the message.
 * \param msg_len the length of the message this function has built.
 * \param Nb the nonce to be hashed and crypted.
 * \returns a byte string that contains the message ready to be sent.
 */
uint8_t* create_m3 (size_t *msg_len, BIGNUM* key, BIGNUM* Nb);

/**
 * This function permits to create in one single shot the fourth message of the D&G protocol.
 * The third message contains the hash of the Na nonce crypted with the session key K. For more
 * information please refer to the protocol report.
 * \param key the session key for encrypting the message.
 * \param msg_len the length of the message this function has built.
 * \param Na the nonce to be hashed and crypted.
 * \returns a byte string that contains the message ready to be sent.
 */
uint8_t* create_m4 (size_t *msg_len, uint8_t* key, BIGNUM* Na);

/**
 * This function contains the key generation algorithm.
 * \param Nb the nounce of the server.
 * \param Na the nounce of the client.
 * \returns the shared session key for secure communication thorugh unsecure channel.
 */
uint8_t *generate_key (BIGNUM *Na, BIGNUM *Nb);

/**
 * This function creates a totally new random nonce. It is a BIGNUM because we need 128 bit of this
 * number and there aren't primitive types that are as long as needed so far.
 * \returns a pointer to a big num structure, initialized to a random value.
 */
BIGNUM *generate_random_nonce (void);

/**
 * This function checks the correctness of the first message of the message. It verify the
 * correctness of the sign present in the message. In this case the sign must belong to the client.
 * \param msg the message received by the server.
 * \returns 0 if the verify process fails
 * \returns 1 otherwise.
 * \returns -1 on error with errno being set consequently.
 */
int verifymessage_m1 (uint8_t *msg, size_t *msg_len);

/**
 * This function checks the correctness of the second message of the protocol.
 * It verify the correctness of the sign present in the message. In this case the sign must
 * belong to the server.
 * It also verify if the nounce Na is the same the client sent before in the message M1.
 * \param msg the message received by the client.
 * \param Na the client-side generated nonce to be verified.
 * \returns 0 if the verify process fails
 * \returns 1 otherwise.
 * \returns -1 on error with errno being set consequently.
 */
int verifymessage_m2 (uint8_t *msg, size_t *msg_len, BIGNUM *Na);

/**
 * This function checks the correctness of the third message of the protocol. It verify if the hash
 * into the message is the same of the hash of the Nb nounce of the server.
 * \param msg the message received by the server.
 * \param Nb the server-side generated nonce.
 * \param key the shared session key in order to decrypt correctly the message.
 * \returns 0 if the verify process fails
 * \returns 1 otherwise.
 * \returns -1 on error with errno being set consequently.
 */
int verifymessage_m3 (uint8_t *msg, size_t *msg_len, BIGNUM *Nb, uint8_t *key);

/**
 * This function checks the correctness of the fourth message of the protocol. It verify if the hash
 * into the message is the same of the hash of the Na nounce of the client.
 * \param msg the message received by the server.
 * \param Na the client-side generated nonce.
 * \param key the shared session key in order to decrypt correctly the message.
 * \returns 0 if the verify process fails
 * \returns 1 otherwise.
 * \returns -1 on error with errno being set consequently.
 */
int verifymessage_m4 (uint8_t *msg, size_t *msg_len, BIGNUM *Na, uint8_t *key);
