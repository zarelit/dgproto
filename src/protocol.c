/**
 * David Costa <david.costa@ieee.org>, Giuliano Peraz <giuliano.peraz@gmail.com>
 */

/**
 * This file contains all the implementation of the header protocol.h in the include directory
 * of this project. It is thought for simplifying the creation of the messages of the protocol.
 * This file must use OpenSSL and return ever a string that has to be freed after use.
 */

#include "../include/protocol.h"
#include "../include/utils.h"

uint8_t*
create_m1 (size_t* msg_len, aid_t id, BIGNUM* Na)
{
	// The whole message M1
    uint8_t* msg;

	// The public key of the server
	EVP_PKEY* skey;
	FILE* skeyfh;


	// Signing related variables
	unsigned char* sig; // actual signature
	size_t siglen; //length of the signature
	unsigned char* Na_value; // Bytes of Na in big-endian format
	size_t Na_size; // Length of Na in bytes


	// Encryption related variables
	EVP_PKEY_CTX* encctx;
	unsigned char* enc; // actual encrypted content
	size_t enclen; // length of the encrypted content

	// Load server key, called server.pem
	skeyfh = fopen("keys/server.pem","r");
	skey = PEM_read_PUBKEY(skeyfh, &skey, NULL, NULL);
	if(!skey){
		fprintf(stderr,"Cannot read server key from file keys/server.pem\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * Step 0: Convert Na in a signable buffer
	 */
	Na_size = BN_num_bytes(Na);
	Na_value = malloc(Na_size);
	BN_bn2bin(Na, Na_value);

	/*
	 * Step 1: Sign Na
	 */
	sig = sign("keys/client.pem", Na_value, Na_size, &siglen);

	/*
	 * Step 2: Encrypt the signed Na using the server public key
	 */
	// create encryption context
	encctx = EVP_PKEY_CTX_new(skey,NULL);
	if (!encctx){
		fprintf(stderr,"Cannot create an encryption context\n");
		exit(EXIT_FAILURE);
	}
	if (EVP_PKEY_encrypt_init(encctx) <= 0){
		fprintf(stderr,"Cannot create an encryption context\n");
		exit(EXIT_FAILURE);
	}

	/* Determine buffer length */
	if (EVP_PKEY_encrypt(encctx, NULL, &enclen, sig, siglen) <= 0)
		exit(EXIT_FAILURE);

	enc = malloc(enclen);
	if (!enc){
		fprintf(stderr,"Out of memory\n");
		exit(EXIT_FAILURE);
	}

	// Do the actual encryption
	if (EVP_PKEY_encrypt(encctx, enc, &enclen, sig, siglen) <= 0){
		fprintf(stderr,"Cannot sign nonce Na\n");
		exit(EXIT_FAILURE);
	}

	// the whole message is encrypted + 1 byte of the id
	*msg_len = enclen + sizeof(id);
	msg = malloc(*msg_len);

	// build the message, prepending the ID and copying the encrypted part.
	msg[0] = id;
	memcpy(&msg[1],enc,enclen);

	/*
	 * Cleanup
	 */
	free(sig);
	free(Na_value);
	free(enc);
    return msg;
}

uint8_t*
create_m2 (size_t* msg_len, aid_t id, BIGNUM* Nb, BIGNUM* Na, uint8_t** iv)
{
    uint8_t *msg; // The message this function is able to build
    uint8_t *enc_part, *plain; // The encrypted part of the message
    size_t sig_len, enc_part_len, iv_len, plain_len;
    EVP_PKEY *cpub_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    FILE* cpub_key_file;
    msg_data msg_parts[3];

    // Get the public key of the client in order to encrypt some part of the message
    cpub_key_file = fopen("keys/client.pub.pem", "r");
    if (cpub_key_file == NULL)
    {
        perror("fopen");
        msg = NULL;
        *msg_len = 0;
        goto exit_create_m2;
    }
    cpub_key = PEM_read_PUBKEY(cpub_key_file, &cpub_key, NULL, NULL);
    if (cpub_key == NULL)
    {
        fprintf(stderr, "Error: can't read client public key\n");
        msg = NULL;
        *msg_len = 0;
        goto exit_create_m2;
    }

    // Create the encrypted part of the message by concatenating Na, Nb and the signature
    msg_parts[0].data_len = BN_bn2bin(Na, msg_parts[0].data);
    msg_parts[1].data_len = BN_bn2bin(Nb, msg_parts[1].data);
    msg_parts[2].data = sign("keys/server.pem", msg_parts[1].data, msg_parts[1].data_len, &sig_len);
    msg_parts[2].data_len = sig_len;
    plain = conc_msgs(&plain_len, 3, msg_parts[0], msg_parts[1], msg_parts[2]);
    if (plain == NULL)
    {
        fprintf(stderr, "Error concatenating parts to be encrypted\n");
        msg = NULL;
        *msg_len = 0;
        goto cleanup_create_m2;
    }

    // Start encryption of plain
    ctx = EVP_PKEY_CTX_new(cpub_key, NULL);
    if (ctx == NULL)
    {
        fprintf(stderr, "Error allocating context for encrypting the message\n");
        msg = NULL;
        *msg_len = 0;
        goto cleanup_create_m2;
    }
    enc_part = NULL;
    if (EVP_PKEY_encrypt(ctx, enc_part, &enc_part_len, plain, plain_len) <= 0)
    {
        fprintf(stderr, "Error during encryption\n");
        msg = NULL;
        *msg_len = 0;
        goto cleanup_create_m2;
    }
    // Create the random Initialization Vector
    *iv = generate_random_aes_iv(&iv_len);
    if (*iv == NULL)
    {
        fprintf(stderr, "Error generating the IV\n");
        msg = NULL;
        *msg_len = 0;
        goto cleanup_create_m2;
    }

    // Create the whole message by concatenating the clear text part and the encrypted one
    msg_parts[0].data = &id;
    msg_parts[0].data_len = sizeof(id);
    msg_parts[1].data = *iv;
    msg_parts[1].data_len = iv_len;
    msg_parts[2].data = enc_part;
    msg_parts[2].data_len = enc_part_len;
    msg = conc_msgs(msg_len, 3, msg_parts[0], msg_parts[1], msg_parts[2]);
    if (msg == NULL)
    {
        fprintf(stderr, "Error concatenating message's parts\n");
        msg = NULL;
        *msg_len = 0;
    }

    // Clean up
    EVP_PKEY_CTX_free(ctx);

cleanup_create_m2:
    fclose(cpub_key_file);
    free(plain);
    free(enc_part);
exit_create_m2:
    return msg;
}

uint8_t*
create_m3 (size_t* msg_len, BIGNUM* key, BIGNUM* Nb, uint8_t* iv)
{
    uint8_t* msg = NULL;
    return msg;
}

uint8_t*
create_m4 (size_t* msg_len, uint8_t* key, BIGNUM* Na, uint8_t* iv)
{
    uint8_t *encr_msg = NULL;
    uint8_t *Na_bin_val;
    size_t Na_len;

    Na_bin_val = malloc(BN_num_bytes(Na));
    Na_len = BN_bn2bin(Na, Na_bin_val);
    encr_msg = do_aes256_crypt(Na_bin_val, key, iv, &Na_len);
    if (encr_msg == NULL)
    {
        fprintf(stderr, "Error crypting the message m3\n");
        *msg_len = 0;
    }
    else
    {
        // Na_len is now storing the real size of the encrypted message
        *msg_len = Na_len;
    }
    free(Na_bin_val);
    return encr_msg;
}

BIGNUM*
generate_random_nonce (void){
	BIGNUM* nonce = BN_new();
	int x;

	if(!nonce){
		fprintf(stderr,"Out of memory\n");
		exit(EXIT_FAILURE);
	}

	x=BN_rand(nonce, 128, 0, 0);
	if(!x){
		fprintf(stderr,"Cannot generate a random nonce\n");
		exit(EXIT_FAILURE);
	}

	return nonce;
}

uint8_t*
generate_key (BIGNUM *Na, BIGNUM *Nb)
{
    uint8_t *key, *tmp;
    size_t tmp_len;
    msg_data key_parts[3];      // Will store Na, Nb and the SALT

    // Create the "message" to be hashed by SHA256 algorithm
    key_parts[0].data_len = BN_bn2bin(Na, key_parts[0].data);
    key_parts[1].data_len = BN_bn2bin(Nb, key_parts[1].data);
    key_parts[2].data = (uint8_t*) &SALT;
    key_parts[2].data_len = SALT_SIZE;
    tmp = conc_msgs(&tmp_len, 3, key_parts[0], key_parts[1], key_parts[2]);
    if (tmp == NULL)
    {
        fprintf(stderr, "Error concatenating parts of the key\n");
        key = NULL;
        goto exit_generate_key;
    }

    // Get the key component hash and make the key from it
    key = do_sha256_digest(tmp, tmp_len);
    free(tmp);
    if (key == NULL)
    {
        fprintf(stderr, "Error creating the key\n");
    }

exit_generate_key:
    return key;
}

int
verifymessage_m1 (uint8_t *msg, size_t *msg_len)
{
    int ret_val = 0;
    BIGNUM* Na;
    msg_data msg1_parts[2]; // Plaintext and ciphertext of M1
    msg_data dec_parts[2];  // The nonce and the signature of the nonce
    uint8_t *dec_msg_part; // Decrypted part of the message
    size_t dec_len;        // Length of dec_msg_part

    // Extract the plaintext and the ciphertext parts of M1
    msg1_parts[0].data = NULL;                  // Will contain the id label of the client
    msg1_parts[0].data_len = sizeof(aid_t);
    msg1_parts[1].data = NULL;                  // Will contain the encrypted part of M1
    msg1_parts[1].data_len = *msg_len - sizeof(aid_t);
    if (extr_msgs(msg, 2, &msg1_parts[0], &msg1_parts[1]) == 0)
    {
        fprintf(stderr, "%s: Error during the extraction of m1 parts\n", __func__);
        ret_val = 0;
        goto exit_verifymessage_m1;
    }

    // Verify the id of the client is correct
    if (*(msg1_parts[0].data) != 'A')
    {
        ret_val = 0;
        fprintf(stderr, "%s: Client is unknown\n", __func__);
        goto exit_verifymessage_m1;
    }

    // Decrypt the crypted part of the message
    dec_msg_part = decrypt("keys/server.pem", msg1_parts[1].data, msg1_parts[1].data_len, &dec_len);

    // Get the nonce Na and its signature
    dec_parts[0].data = NULL;                   // Will contain Na
    dec_parts[0].data_len = NONCE_LEN;
    dec_parts[1].data = NULL;                   // Will contain Na signature by the client
    dec_parts[1].data_len = dec_len - dec_parts[0].data_len;
    ret_val = extr_msgs(dec_msg_part, 2, &dec_parts[0], &dec_parts[1]);
    if (ret_val == 0)
    {
        fprintf(stderr, "%s: Error during the extraction of decrypted parts\n", __func__);
        goto exit_verifymessage_m1;
    }

    // Verify the correcteness of the signature of Na
    Na = BN_bin2bn(dec_parts[0].data, dec_parts[0].data_len, NULL);
    if (Na == NULL)
    {
        fprintf(stderr, "%s: Error extracting Na from raw bits\n", __func__);
        ret_val = 0;
        goto exit_verifymessage_m1;
    }
    if (verify("keys/client.pub.pem", Na, dec_parts[1].data, dec_parts[1].data_len) == 0)
    {
        fprintf(stderr, "%s: Error during Na signature verifing", __func__);
        ret_val = 0;
        goto exit_verifymessage_m1;
    }
    ret_val = 1;

exit_verifymessage_m1:
    // Cleanup if needed
    if (Na != NULL) BN_clear_free(Na);
    if (msg1_parts[0].data != NULL) free(msg1_parts[0].data);
    if (msg1_parts[1].data != NULL) free(msg1_parts[1].data);
    if (dec_parts[0].data != NULL) free(dec_parts[0].data);
    if (dec_parts[1].data != NULL) free(dec_parts[1].data);
    return ret_val;
}

int
verifymessage_m2 (uint8_t *msg, size_t *msg_len, BIGNUM *Na)
{
    return 0;
}

int
verifymessage_m3 (uint8_t *msg, size_t *msg_len, BIGNUM *Nb, uint8_t *key)
{
    /* {H(Nb)} */
    return 0;
}

int
verifymessage_m4 (uint8_t *msg, size_t *msg_len, BIGNUM *Na, uint8_t *key)
{
    return 0;
}
