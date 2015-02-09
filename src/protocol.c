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
#include "../include/common.h"

uint8_t*
create_m1 (size_t* msg_len, aid_t id, BIGNUM* Na_bn)
{

	// The whole message
	msg_data m1;

	// The id
	msg_data myid;

	// Nonce generated by the client
	msg_data Na;

	// Signature of the nonce
	msg_data sigNa;

	// Encrypted part of M1: {Na,sign(Na)}
	msg_data signedNa; // That is, the plaintext of encryptedNa
	msg_data encryptedNa;

	// IV of the seal and the key
	msg_data iv;
	msg_data ek;
	int eklen;

	// Convert the nonce in a bytestring
	Na.data = malloc(BN_num_bytes(Na_bn));
	Na.data_len = BN_bn2bin(Na_bn, Na.data);
	if(!Na.data || Na.data_len != (NONCE_LEN/8)){
		fprintf(stderr,"Error handling Na\n");
		exit(EXIT_FAILURE);
	}

	// Sign Na with our private key
	sigNa.data = sign(CLIENT_KEY, Na.data, Na.data_len, &(sigNa.data_len));

	// Build Na || sig(Na), then cipher it
	signedNa.data = conc_msgs(&(signedNa.data_len), 2, Na, sigNa);
	encryptedNa.data = encrypt(SERVER_PUBKEY, signedNa.data, signedNa.data_len, &(encryptedNa.data_len),
						&(iv.data), &(iv.data_len), &(ek.data), &eklen);
	ek.data_len = eklen;

	// Add the id
	myid.data = &id;
	myid.data_len = sizeof(id);

	m1.data = conc_msgs(&(m1.data_len), 4, myid, iv, ek, encryptedNa);

	//dump("ID",myid.data,myid.data_len);
	//dump("IV",iv.data,iv.data_len);
	//dump("EK",ek.data,ek.data_len);
	//dump("whole envelope", encryptedNa.data, encryptedNa.data_len);

	// cleanup
	free(Na.data);
	free(sigNa.data);
	free(signedNa.data);
	free(encryptedNa.data);
	free(iv.data);
	free(ek.data);

	*msg_len = m1.data_len;
	return m1.data;
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

    // Input error checking
    if (msg_len == NULL || Nb == NULL || Na == NULL || iv == NULL)
    {
        fprintf(stderr, "%s: Invalid parameter passed\n", __func__);
        msg = NULL;
        *msg_len = 0;
        goto exit_create_m2;
    }

    // Get the public key of the client in order to encrypt some part of the message
    cpub_key_file = fopen(CLIENT_PUBKEY, "r");
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
    msg_parts[2].data = sign(SERVER_KEY, msg_parts[1].data, msg_parts[1].data_len, &sig_len);
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
    uint8_t *encr_msg, *Na_digest;
    uint8_t *Na_bin_val;
    size_t Na_len, enc_len;

    // Input error checking
    if (msg_len == NULL || key == NULL || Na == NULL || iv == NULL)
    {
        fprintf(stderr, "%s: Invalid parameter passed\n", __func__);
        encr_msg = NULL;
        *msg_len = 0;
        goto exit_create_m4;
    }

    // Create the message by hashing the Na and encrypt it by means of key key
    Na_bin_val = malloc(BN_num_bytes(Na));
    Na_len = BN_bn2bin(Na, Na_bin_val);
    Na_digest = do_sha256_digest(Na_bin_val, Na_len);
    if (Na_digest == NULL)
    {
        fprintf(stderr, "Error building the digest for Na\n");
        encr_msg = NULL;
        *msg_len = 0;
        free(Na_bin_val);
        goto exit_create_m4;
    }
    encr_msg = do_aes256_crypt(Na_bin_val, key, iv, &enc_len);
    if (encr_msg == NULL)
    {
        fprintf(stderr, "Error crypting the message m4\n");
        *msg_len = 0;
    }
    else
    {
        *msg_len = enc_len;
    }
    free(Na_bin_val);

exit_create_m4:
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

	x=BN_rand(nonce, NONCE_LEN, 0, 0);
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

    // Input error checking
    if (Na == NULL || Nb == NULL)
    {
        key = NULL;
        fprintf(stderr, "%s: Invalid parameter passed\n", __func__);
        goto exit_generate_key;
    }

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
verifymessage_m1 (uint8_t *msg, size_t msg_len, BIGNUM** Na)
{
    int ret_val = 0;
    BIGNUM *client_nonce;
    msg_data msg1_parts[2]; // Plaintext and ciphertext of M1
    msg_data dec_parts[2];  // The nonce and the signature of the nonce
    uint8_t *dec_msg_part; // Decrypted part of the message
    size_t dec_len;        // Length of dec_msg_part

    // Input error checking
    if (msg == NULL || msg_len == 0 || Na == NULL)
    {
        ret_val = 0;
        fprintf(stderr, "%s: Invalid parameter passed\n", __func__);
        goto exit_verifymessage_m1;
    }

    // Extract the plaintext and the ciphertext parts of M1
    msg1_parts[0].data = NULL;                  // Will contain the id label of the client
    msg1_parts[0].data_len = sizeof(aid_t);
    msg1_parts[1].data = NULL;                  // Will contain the encrypted part of M1
    msg1_parts[1].data_len = msg_len - sizeof(aid_t);
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
    dec_msg_part = decrypt(SERVER_KEY, msg1_parts[1].data, msg1_parts[1].data_len, &dec_len);

    // Get the nonce client_nonce and its signature
    dec_parts[0].data = NULL;                   // Will contain Na
    dec_parts[0].data_len = NONCE_LEN;
    dec_parts[1].data = NULL;                   // Will contain Na's signature by the client
    dec_parts[1].data_len = dec_len - dec_parts[0].data_len;
    ret_val = extr_msgs(dec_msg_part, 2, &dec_parts[0], &dec_parts[1]);
    if (ret_val == 0)
    {
        fprintf(stderr, "%s: Error during the extraction of decrypted parts\n", __func__);
        goto exit_verifymessage_m1;
    }

    // Verify the correcteness of the signature of Na
    client_nonce = BN_bin2bn(dec_parts[0].data, dec_parts[0].data_len, NULL);
    if (client_nonce == NULL)
    {
        fprintf(stderr, "%s: Error extracting client_nonce from raw bits\n", __func__);
        ret_val = 0;
        goto exit_verifymessage_m1;
    }
    if (verify(CLIENT_PUBKEY, client_nonce, dec_parts[1].data, dec_parts[1].data_len) == 0)
    {
        fprintf(stderr, "%s: Error during client_nonce signature verifing", __func__);
        ret_val = 0;
        goto exit_verifymessage_m1;
    }
    *Na = BN_dup(client_nonce);
    if (*Na == NULL)
    {
        ret_val = 0;
        fprintf(stderr, "Error copying client_nonce to Na\n");
    }
    else
    {
        ret_val = 1;
    }


exit_verifymessage_m1:
    // Cleanup if needed
    if (client_nonce != NULL) BN_clear_free(client_nonce);
    if (msg1_parts[0].data != NULL) free(msg1_parts[0].data);
    if (msg1_parts[1].data != NULL) free(msg1_parts[1].data);
    if (dec_parts[0].data != NULL) free(dec_parts[0].data);
    if (dec_parts[1].data != NULL) free(dec_parts[1].data);
    return ret_val;
}

int
verifymessage_m2 (uint8_t *msg, size_t *msg_len, BIGNUM *Na, BIGNUM **Nb)
{
	// Message is B|enc(Na|Nb|sign(Nb))
	// Define its components
	msg_data id;
	msg_data encryptedPart;
	msg_data receivedNa;
	msg_data signedNb;
	msg_data receivedNb;

	// Auxiliary variables
	int s=1;
	int ret;
	msg_data temp;
	BIGNUM* receivedNaBN=NULL;

	// Split ID from encrypted part
	id.data_len=sizeof(aid_t);
	encryptedPart.data_len = *msg_len - id.data_len;
    ret = extr_msgs(msg, 2, &id, &encryptedPart);
	if(!ret) s=0;

	// Verify ID
	if(id.data[0] != 'B') s=0;

	// Decode the encrypted part
	temp.data = decrypt(CLIENT_KEY,encryptedPart.data, encryptedPart.data_len, &(temp.data_len));

	// Split Na, Nb, sig of Nb
	receivedNa.data_len = NONCE_LEN/8;
	receivedNb.data_len = NONCE_LEN/8;
	signedNb.data_len = temp.data_len - (receivedNa.data_len + receivedNb.data_len);
	ret = extr_msgs(temp.data, 3, receivedNa, receivedNb, signedNb);
	if(!ret) s=0;

	// Verify that received nonce is actually our generate Nonce
	receivedNaBN = BN_bin2bn(receivedNa.data, receivedNa.data_len, receivedNaBN);
	if(BN_cmp(Na,receivedNaBN)!= 0) s=0;

	// Pack received Nb in a bignum and then verify the signature
	*Nb = BN_bin2bn(receivedNb.data, receivedNb.data_len, *Nb);
	ret = verify(SERVER_PUBKEY, *Nb, signedNb.data, signedNb.data_len);
	if(!ret) s=0;

	// Cleanup
	free(id.data);
	free(encryptedPart.data);
	free(receivedNa.data);
	free(signedNb.data);
	free(receivedNb.data);
	free(temp.data);
	BN_free(receivedNaBN);

    if(s==0) return 0;
	else return 1;
}

int
verifymessage_m3 (uint8_t* msg, size_t msg_len, BIGNUM* Nb, uint8_t* key, uint8_t* iv)
{
    uint8_t *srv_dig; // Server digest, the hash of Nb computed locally
    uint8_t *cli_dig; // The SHA256(Nb) sent by the client
    uint8_t *Nb_bin_val;
    uint8_t ret_val;
    size_t cli_dig_len, Nb_len;

    // Input error checking
    if (msg == NULL || msg_len == 0 || Nb == NULL || key == NULL)
    {
        ret_val = 0;
        fprintf(stderr, "%s: Invalid parameter passed\n", __func__);
        goto exit_verifymessage_m3;
    }

    // Decrypt the message by means of the key
    cli_dig = do_aes256_decrypt(msg, key, iv, &cli_dig_len);
    if (cli_dig == NULL)
    {
        fprintf(stderr, "Error decrypting message m3\n");
        ret_val = 0;
        goto exit_verifymessage_m3;
    }

    // Compute the digest of server-generated Nb
    Nb_len = BN_num_bytes(Nb);
    Nb_bin_val = malloc(Nb_len);
    BN_bn2bin(Nb, Nb_bin_val);
    srv_dig = do_sha256_digest(Nb_bin_val, Nb_len);
    if (srv_dig == NULL)
    {
        fprintf(stderr, "Error during the hashing of the message m3\n");
        ret_val = 0;
        free(Nb_bin_val);
        goto exit_verifymessage_m3;
    }

    // Check if the digests are the same
    ret_val = (memcmp(srv_dig, cli_dig, 256) != 0)? 0 : 1;

exit_verifymessage_m3:
    return ret_val;
}

int
verifymessage_m4 (uint8_t *msg, size_t *msg_len, BIGNUM *Na, uint8_t *key)
{
    return 0;
}
