/**
 * David Costa <david.costa@ieee.org>, Giuliano Peraz <giuliano.peraz@gmail.com>
 */

#include <sys/socket.h>
#include <stdio.h>
#include <stdint.h>
#include <openssl/bn.h>

/**
 * Wrapper around send() that manages partial transmissions
 *
 * \param sock an already connected TCP socket
 * \param buf pointer to the data
 * \param len length of the data to be sent in bytes
 */
void sendbuf(int sock, unsigned char* buf, ssize_t len);

/**
 * writes to a file descriptor the hexdump of buf
 * \param fh the file used for output. can be stderr, for example
 */
void hexdump(FILE* fh, unsigned char* buf, size_t buflen);


/**
 * It permits to encrypt the message <b>msg</b> with the key <b>key</b> using AES 256
 * bit encryption algorithm.
 * \param msg the message to be encrypted.
 * \param key the key you need for encryption.
 * \param msg_len the length of msg, if the function succeed this variable will store the length
 * of the encrypted message.
 * \returns a string of bytes which contains the encrypted message or NULL in case of error.
 */
uint8_t* do_aes256_crypt (uint8_t* msg, uint8_t* key, uint8_t* iv, size_t* msg_len);

/**
 * It permits to decrypt the message <b>msg</b> with the key <b>key</b> using AES 256
 * bit decryption algorithm.
 * \param msg the message to be decrypted.
 * \param key the key you need for decryption.
 * \param msg_len the length of msg, if the function succeed this variable will store the length
 * of the decrypted message.
 * \returns a string of bytes which contains the decrypted message or NULL in case of error.
 */
uint8_t* do_aes256_decrypt (uint8_t* enc_msg, uint8_t* key, uint8_t* iv, size_t* msg_len);

/**
 * Sign something
 * \param keypath is a string with the path to a PEM private key
 * \param payload is the string to be signed
 * \param plen is the length of payload in bytes
 * \param slen is the actual length of the signed content
 * \returns a buffer with the signed content.
 * \warning the result is dynamically allocated. Memory must be freed manually.
 */
uint8_t*
sign(const char* keypath, const uint8_t* payload, const size_t plen, size_t* slen);

/**
 * Verify the signature of a nonce
 * \param keypath is a string with the path to a PEM public key
 * \param nonce is the nonce to be verified
 * \param slen is the actual length of the signature
 * \returns whether the signature is valid or not - 0 is not valid
 */
int verify(const char* keypath, BIGNUM* nonce, const uint8_t* sig, size_t slen);
