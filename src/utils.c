/**
 * David Costa <david.costa@ieee.org>, Giuliano Peraz <giuliano.peraz@gmail.com>
 */

#include "../include/utils.h"
#include "../include/common.h"

void sendbuf(int sock, unsigned char* buf, ssize_t len){
	ssize_t sent=0;
	ssize_t n=0;

	while(sent != len){
		// Always try to send the whole buffer
		n = send(sock, &buf[sent], len - sent, 0);

		// Check for errors or update the index of what has already been sent
		if(n != -1){
			sent += n;
		} else{
			perror("Cannot send data to server");
			exit(EXIT_FAILURE);
		}
	}
}

void hexdump(FILE *fh, unsigned char* buf, size_t buflen){
	int i;

	for(i=0; i<buflen; i++){
		fprintf(fh,"%02hhX",buf[i]);
	}
}

/**
 * This function reads the Initialization Vector (IV) from the file path passed by parameter.
 * \param iv_file the Initialization Vector for the cipher.
 * \returns a buffer that contains the IV or NULL if an error has occourred.
 */
uint8_t*
read_iv_from_file (FILE* iv_file)
{
    uint8_t *iv_buf;
    size_t byte_read;

    iv_buf = malloc(EVP_MAX_IV_LENGTH);
    byte_read = fread((void*) iv_buf, sizeof(uint8_t), EVP_MAX_IV_LENGTH, iv_file);
    if(byte_read < EVP_MAX_IV_LENGTH * sizeof(uint8_t))
    {
        fprintf(stderr, "Can't read the whole IV\n");
        if(feof(iv_file) > 0)
        {
            fprintf(stderr, "EOF reached before expected\n");
        }
        else if (ferror > 0)
        {
            fprintf(stderr, "Error reading the file\n");
        }
        free(iv_buf);
    }
    return iv_buf;
}

uint8_t*
do_aes256_crypt (uint8_t* msg, uint8_t* key, uint8_t* iv, size_t* msg_len)
{
    EVP_CIPHER_CTX *ctx;
    uint8_t *encr_msg;
    size_t enc_len; // Encypted message length and block size of the cipher
    const size_t bsize = EVP_CIPHER_block_size(EVP_aes_256_cbc());

    if (iv == NULL || msg == NULL || key == NULL || *msg_len < 0)
    {
        fprintf(stderr, "Error: invalid argument passed");
        encr_msg = NULL;
        *msg_len = 0;
        goto exit_do_aes256_crypt;
    }

    // Finally do the encryption
    encr_msg = malloc(*msg_len + bsize);
    ctx = malloc(sizeof(EVP_CIPHER_CTX));
    EVP_CIPHER_CTX_Init(ctx);
    if (EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key, iv) == 0)
    {
        fprintf(stderr, "Error initializing the encryption\n");
        free(encr_msg);
        *msg_len = 0;
        goto exit_do_aes256_crypt;
    }
    enc_len = 0;
    if (EVP_EncryptUpdate(ctx, encr_msg, &enc_len, msg, *msg_len) == 0)
    {
        fprintf(stderr, "Error during the encryption\n");
        free(encr_msg);
        *msg_len = 0;
        goto exit_do_aes256_crypt;
    }
    if (EVP_EncryptFinal(ctx, encr_msg + enc_len, msg_len) == 0)
    {
        fprintf(stderr, "Error finalizing the encryption\n");
        free(encr_msg);
        *msg_len = 0;
        goto exit_do_aes256_crypt;
    }
    *msg_len += enc_len;
exit_do_aes256_crypt:
    EVP_CIPHER_CTX_cleanup(ctx);
    free(ctx);
    return encr_msg;
}

uint8_t*
do_aes256_decrypt (uint8_t* enc_msg, uint8_t* key, uint8_t* iv, size_t* msg_len)
{
    EVP_CIPHER_CTX *ctx;
    uint8_t *dec_msg;
    size_t enc_len; // Encypted message length and block size of the cipher
    const size_t bsize = EVP_CIPHER_block_size(EVP_aes_256_cbc());

    if (iv == NULL || msg == NULL || key == NULL || *msg_len < 0)
    {
        fprintf(stderr, "Error: invalid argument passed");
        encr_msg = NULL;
        *msg_len = 0;
        goto exit_do_aes256_decrypt;
    }

    // Finally do the encryption
    dec_msg = malloc(*msg_len + bsize);
    ctx = malloc(sizeof(EVP_CIPHER_CTX));
    EVP_CIPHER_CTX_Init(ctx);
    if (EVP_DecryptInit(ctx, EVP_aes_256_cbc(), key, iv) == 0)
    {
        fprintf(stderr, "Error initializing the encryption\n");
        free(dec_msg);
        *msg_len = 0;
        goto exit_do_aes256_decrypt;
    }
    dec_len = 0;
    if (EVP_DecryptUpdate(ctx, enc_msg, &dec_len, msg, *msg_len) == 0)
    {
        fprintf(stderr, "Error during the encryption\n");
        free(enc_msg);
        *msg_len = 0;
        goto exit_do_aes256_decrypt;
    }
    if (EVP_DecryptFinal(ctx, dec_msg + dec_len, msg_len) == 0)
    {
        fprintf(stderr, "Error finalizing the encryption\n");
        free(enc_msg);
        *msg_len = 0;
        goto exit_do_aes256_decrypt;
    }
    *msg_len += dec_len;
    exit_do_aes256_decrypt:
    EVP_CIPHER_CTX_cleanup(ctx);
    free(ctx);
    return dec_msg;
}