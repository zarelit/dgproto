/**
 * David Costa <david.costa@ieee.org>, Giuliano Peraz <giuliano.peraz@gmail.com>
 */

#include <sys/socket.h>
#include <stdio.h>
#include <stdint.h>

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