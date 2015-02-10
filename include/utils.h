/**
 * David Costa <david.costa@ieee.org>, Giuliano Peraz <giuliano.peraz@gmail.com>
 */

#include <sys/socket.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <stdarg.h>

#define say(yeah) printf("%s\n",yeah)
#define dump(name, quantity, length) printf("%s length: %d\n", name, length);\
									 printf("%s dump:\n", name);\
									 hexdump(stdout,quantity, length);\
									 printf("\n");
#define doing(something) printf("** "); say(something);

//! How much of the file we work with at a time
#define CHUNK_SIZE 512

/**
 * \struct msg_data
 * \brief Structure for the data part of any possible message.
 * \details The structure contains a pointer to the data of the message and the length in bytes
 * of the data itself. This structure is very useful for concatenating parts of a message
 */
typedef struct message_data
{
    /*! Binary data of the message.*/
    uint8_t* data;
    /*! Length in bytes of the \ref msg_data::data "data" field of this struct.*/
    size_t data_len;
} msg_data;

/**
 * This function concatenates the msg_data structures passed by parameter in one single data
 * structure. This function accepts a variable number of arguments in order to add all the messages
 * that has to be concatenated.
 * \param[out] buf_len A pointer used for storing the length of the resulting concatenated message.
 * \param[in] argc How many msg_data have been passed to this function
 * \param[in] ... A variable ordered list of msg_data structures which will be concatenated.
 * \returns A pointer to a buffer where is stored the entire message composed by the msg_data
 * structures passed by parameters or NULL if errors occourred.
 */
uint8_t* conc_msgs (size_t* buf_len, size_t argc, ...);

/**
 * This function makes possible to extract all the fields inside a byte buffer given by parameter.
 * It uses a variable argument list of type \ref msg_data where each \ref msg_data struct has its
 * \ref msg_data::data "data" field equals to NULL. For example:
 * \code{.c}
 * // This code explains how to use this function for extracting 3 msg_data structure from the
 * // buffer buf
 * void foo (uint8_t* buf, size_t buf_len)
 * {
 *      msg_data msgs[3];
 *      msgs[0].data = msgs[1].data = msgs[2].data = NULL;
 *      // First message is 10 byte long
 *      msgs[0].data_len = 10;
 *      msgs[1].data_len = 8;
 *      msgs[2].data_len = 4;
 *      if (extr_msgs(buf, buf_len, 3, &msgs[0], &msgs[1], &msgs[2]) == 0)
 *      {
 *              // Error management
 *      }
 *      // Do something with the message list
 * }
 * \endcode
 * The function allocates the memory for each \ref msg_data::data "data" field of each message
 * being passed by parameter.
 * \param[in] buffer The buffer that contains the concatenated datas.
 * \param[in] buf_len Length of the buffer in bytes.
 * \param[in] argc Number of the element of the list of \ref msg_data structure pointers.
 * \param[out] ... List of \ref msg_data structure pointers with all data field set to NULL and
 * data_len field set to a number different from 0, of course.
 * \return 1 if all operations succeed, 0 otherwise.
 * \warning All the \ref msg_data pointers have the \ref msg_data::data "data" field allocated
 * in memory, so freeing that memory is user's business.
 */
uint8_t extr_msgs (uint8_t* buffer, size_t argc, ...);

/**
 * Wrapper around send() that manages partial transmissions
 *
 * \param sock an already connected TCP socket
 * \param buf pointer to the data
 * \param len length of the data to be sent in bytes
 * \returns 1 if sending has succeeded, 0 otherwise.
 */
uint8_t sendbuf(int sock, unsigned char* buf, ssize_t len);

/**
 * writes to a file descriptor the hexdump of buf
 * \param fh the file used for output. can be stderr, for example
 */
void hexdump(FILE* fh, unsigned char* buf, size_t buflen);

/**
 * It permits to encrypt the message <b>msg</b> with the key <b>key</b> using AES 256
 * bit encryption algorithm.
 * \param[in] msg the message to be encrypted.
 * \param[in] msg_len length of the message to be encrypted.
 * \param[in] key the key you need for encryption.
 * \param[in] iv the initialization vector for the cipher to crypt.
 * \param[out] enc_len the length of msg, if the function succeed this variable will store the length
 * of the encrypted message, otherwise it will be equal to 0.
 * \returns a string of bytes which contains the encrypted message or NULL in case of error.
 */
uint8_t* do_aes256_crypt (uint8_t* msg, size_t msg_len, uint8_t* key, uint8_t* iv, size_t* enc_len);

/**
 * It permits to decrypt the message <b>msg</b> with the key <b>key</b> using AES 256
 * bit decryption algorithm.
 * \param enc_msg the message to be decrypted.
 * \param enc_len the length of the message to be decrypted.
 * \param key the key you need for decryption.
 * \param iv the initialization vector for the cipher.
 * \param msg_len the length of msg, if the function succeed this variable will store the length
 * of the decrypted message, otherwise it will be equal to 0.
 * \param iv the initialization vector for the cipher to crypt.
 * \returns a string of bytes which contains the decrypted message or NULL in case of error.
 */
uint8_t* do_aes256_decrypt (uint8_t* enc_msg, size_t enc_len , uint8_t* key, uint8_t* iv, size_t* msg_len);

/**
 * Signs a buffer using a private key
 * \param keypath is a string with the path to a PEM private key
 * \param payload is the string to be signed
 * \param plen is the length of payload in bytes
 * \param slen is the actual length of the signed content
 * \returns a buffer with the signed content or NULL if errors occourred.
 * \warning the result is dynamically allocated. Memory must be freed manually.
 */
uint8_t* sign(const char* keypath, const uint8_t* payload, const size_t plen, size_t* slen);

/**
 * This function is in charge of creating a random Initialization Vector for an AES cipher.
 * \param iv_len a pointer where the function will store the length of the iv.
 * \returns a pointer to a buffer of iv_len bytes or NULL in case of error.
 */
uint8_t* generate_random_aes_iv (size_t* iv_len);

/**
 * Verify the signature of a nonce
 * \param keypath is a string with the path to a PEM public key
 * \param nonce is the nonce to be verified
 * \param sig the signature of the nonce to be verified
 * \param slen is the actual length of the signature
 * \returns whether the signature is valid or not - 0 is not valid or errors occourred.
*/
int verify(const char* keypath, BIGNUM* nonce, const uint8_t* sig, size_t slen);

/**
 * The function computes the SHA256 of the message passed by parameter.
 * \param msg the message the hash has to be computed.
 * \param msg_len the length in bytes of the message.
 * \returns a pointer to a byte string containing the SHA256 of the message, or NULL if errors
 * occourred.
 */
uint8_t* do_sha256_digest (uint8_t* msg, size_t msg_len);

/**
 * Encrypts a buffer with a public key
 * \param keypath is a string with the path to a PEM public key
 * \param p is the buffer containing the plaintext
 * \param plen is the length of the plaintext
 * \param[out] clen is the length of the returned ciphertext
 * \param[out] iv is the buffer containing the generated IV of the seal
 * \param[out] ivlen is the length of the iv buffer
 * \param ek is the envelope key
 * \param ekl is the length of the envelope key
 * \returns a pointer to the ciphertext or NULL if errors occourred.
 */
uint8_t* encrypt(const char* keypath, const uint8_t* p, const size_t plen, size_t* clen, uint8_t** iv, size_t* ivlen, uint8_t** ek, size_t* ekl);

/**
 * Decrypts a buffer with a private key
 * \param keypath is a string with the path to a PEM private key
 * \param p is the buffer containing the ciphertext
 * \param plen is the length of the ciphertext
 * \param clen is the length of the returned plaintext
 * \param iv is a buffer with the IV for the envelope
 * \returns a pointer to the plaintext or NULL if errors occourred.
 */
uint8_t* decrypt(const char* keypath, const uint8_t* c, const size_t clen, size_t* plen, uint8_t* iv, uint8_t* ek, size_t ekl);

/**
 * Receive buffer
 * \param s an already opened socket
 * \param len number of bytes to wait from the socket
 * \returns a pointer to a buffer containing len bytes or NULL in case of error
 */
uint8_t* recvbuf(int s, size_t len);

/**
 * Sends a whole file through a socket
 * \param s a connected socket
 * \param file a opened and readable regular file
 * \return 0 in case of fail, 1 otherwise
 */
uint8_t sendfile(int s, FILE* file, uint8_t* key, uint8_t* iv);

