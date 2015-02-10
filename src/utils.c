/**
 * David Costa <david.costa@ieee.org>, Giuliano Peraz <giuliano.peraz@gmail.com>
 */

#include "../include/utils.h"
#include "../include/common.h"

uint8_t*
conc_msgs (size_t* buf_len, size_t argc, ...)
{
    va_list msgs;
    msg_data msg;
    uint8_t *buffer, *tmp;
    size_t el_cnt; // ELement CouNTer

    // Input error checking
    if (buf_len == NULL || argc == 0)
    {
        buffer = NULL;
        fprintf(stderr, "Invalid argument\n");
        goto exit_conc_msgs;
    }

    // Compute the total number of bytes the buffer has to have
    *buf_len = 0;
    va_start(msgs, argc);
    for (el_cnt = 0; el_cnt < argc; el_cnt ++)
    {
        msg = va_arg(msgs, msg_data);
        if (msg.data == NULL || msg.data_len == 0)
        {
            buffer = NULL;
            *buf_len = 0;
            fprintf(stderr, "Element number %d of the list is not correct\n",(int) el_cnt);
            goto exit_conc_msgs;
        }
        *buf_len += msg.data_len;
    }
    va_end(msgs);

    // Copy the data into the buffer
    buffer = malloc(sizeof(uint8_t) * (*buf_len));
    if (buffer == NULL)
    {
        fprintf(stderr, "Out of memory\n");
        goto exit_conc_msgs;
    }
    tmp = buffer;
    va_start(msgs, argc);
    for (el_cnt = 0; el_cnt < argc; el_cnt ++)
    {
        msg = va_arg(msgs, msg_data);
        memcpy(tmp, msg.data, msg.data_len);
        tmp += msg.data_len;
    }
    va_end(msgs);

exit_conc_msgs:
    return buffer;
}

uint8_t
extr_msgs (uint8_t* buffer, size_t argc, ...)
{
    va_list msgs;
    uint8_t ret_val = 0;
    uint8_t *data_p; // Data pointer
    size_t el_cnt;   // ELement CouNTer
    msg_data *msg;

    // Input error checking
    if (argc == 0)
    {
        fprintf(stderr, "Parameter argc is 0\n");
        goto exit_extr_msgs;
    }

    // Extract the messages of the buffer
    va_start(msgs, argc);
    data_p = buffer;
    for (el_cnt = 0; el_cnt < argc; el_cnt ++)
    {
        msg = va_arg(msgs, msg_data*);
        if (msg == NULL)
        {
            fprintf(stderr, "Pointer number %d of the list is NULL\n", (int) el_cnt);
            break;
        }
        if (msg -> data_len == 0)
        {
            fprintf(stderr, "Data len of the element number %d of the list is 0\n", (int) el_cnt);
            break;
        }
        msg -> data = malloc(sizeof(uint8_t) * msg -> data_len);
        memcpy(msg -> data, data_p, msg -> data_len);
        data_p += msg -> data_len;
    }
    va_end(msgs);
    ret_val = 1;

    exit_extr_msgs:
    return ret_val;
}

uint8_t sendbuf(int sock, unsigned char* buf, ssize_t len){
    ssize_t sent = 0;
    ssize_t n = 0;
    uint8_t ret_val = 1;

    while(sent != len){
        // Always try to send the whole buffer
        n = send(sock, &buf[sent], len - sent, 0);

        // Check for errors or update the index of what has already been sent
        if(n != -1){
            sent += n;
        } else{
            perror("Cannot send data to server\n");
            ret_val = 0;
            break;
        }
    }
    return ret_val;
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
do_aes256_crypt (uint8_t* msg, size_t msg_len, uint8_t* key, uint8_t* iv, size_t* enc_len)
{
    EVP_CIPHER_CTX *ctx;
    uint8_t *encr_msg;
    int temp_enc_len; // Encrypted message length and block size of the cipher
    const size_t bsize = EVP_CIPHER_block_size(EVP_aes_256_cbc());

    // Input error checking
    if (iv == NULL || msg == NULL || key == NULL || msg_len <= 0)
    {
        fprintf(stderr, "Error: invalid argument passed");
        encr_msg = NULL;
        *enc_len = 0;
        goto exit_do_aes256_crypt;
    }

    // Allocate all the needed data structures
    encr_msg = malloc(msg_len + bsize);
    if (encr_msg == NULL)
    {
        fprintf(stderr, "%s: Out of memory allocating of encr_msg\n", __func__);
        *enc_len = 0;
        goto exit_do_aes256_crypt;
    }
    ctx = malloc(sizeof(EVP_CIPHER_CTX));
    if (ctx == NULL)
    {
        fprintf(stderr, "%s: Out of memory allocating of ctx\n", __func__);
        free(encr_msg);
        encr_msg = NULL;
        *enc_len = 0;
        goto exit_do_aes256_crypt;
    }
    EVP_CIPHER_CTX_init(ctx);
    if (EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key, iv) == 0)
    {
        fprintf(stderr, "Error initializing the encryption\n");
        free(encr_msg);
        encr_msg = NULL;
        *enc_len = 0;
        goto cleanup_do_aes256_crypt;
    }
    temp_enc_len = 0;
    if (EVP_EncryptUpdate(ctx, encr_msg, &temp_enc_len, msg, msg_len) == 0)
    {
        fprintf(stderr, "Error during the encryption\n");
        free(encr_msg);
        encr_msg = NULL;
        *enc_len = 0;
        goto cleanup_do_aes256_crypt;
    }
    *enc_len = temp_enc_len;
    if (EVP_EncryptFinal(ctx, encr_msg + temp_enc_len, &temp_enc_len) == 0)
    {
        fprintf(stderr, "Error finalizing the encryption\n");
        free(encr_msg);
        encr_msg = NULL;
        *enc_len = 0;
        goto cleanup_do_aes256_crypt;
    }
    *enc_len += temp_enc_len;

cleanup_do_aes256_crypt:
    EVP_CIPHER_CTX_cleanup(ctx);
    free(ctx);

exit_do_aes256_crypt:
    return encr_msg;
}

uint8_t*
do_aes256_decrypt (uint8_t* enc_msg, size_t enc_len , uint8_t* key, uint8_t* iv, size_t* msg_len)
{
    EVP_CIPHER_CTX *ctx;
    uint8_t *dec_msg;
    int dec_len; // Encypted message length and block size of the cipher
    const size_t bsize = EVP_CIPHER_block_size(EVP_aes_256_cbc());

    if (iv == NULL || enc_msg == NULL || key == NULL || enc_len <= 0)
    {
        fprintf(stderr, "Error: invalid argument passed\n");
        dec_msg = NULL;
        *msg_len = 0;
        goto exit_do_aes256_decrypt;
    }

    // Finally do the encryption
    dec_msg = malloc(enc_len + bsize);
    if (dec_msg == NULL)
    {
        fprintf(stderr, "%s: Out of memory be allocating of dec_msg\n", __func__);
        *msg_len = 0;
        goto exit_do_aes256_decrypt;
    }
    ctx = malloc(sizeof(EVP_CIPHER_CTX));
    if (ctx == NULL)
    {
        fprintf(stderr, "%s: Out of memory allocating of ctx\n", __func__);
        free(dec_msg);
        dec_msg = NULL;
        *msg_len = 0;
        goto exit_do_aes256_decrypt;
    }
    EVP_CIPHER_CTX_init(ctx);
    if (EVP_DecryptInit(ctx, EVP_aes_256_cbc(), key, iv) == 0)
    {
        fprintf(stderr, "Error initializing the decryption\n");
        free(dec_msg);
        *msg_len = 0;
        goto exit_do_aes256_decrypt;
    }
    dec_len = 0;
    if (EVP_DecryptUpdate(ctx, dec_msg, &dec_len, enc_msg, enc_len) == 0)
    {
        fprintf(stderr, "Error during the decryption\n");
        free(dec_msg);
        *msg_len = 0;
        goto exit_do_aes256_decrypt;
    }
    if (EVP_DecryptFinal(ctx, dec_msg + dec_len, &dec_len) == 0)
    {
        fprintf(stderr, "Error finalizing the decryption\n");
        free(dec_msg);
        *msg_len = 0;
        goto exit_do_aes256_decrypt;
    }
    *msg_len += dec_len;

exit_do_aes256_decrypt:
    EVP_CIPHER_CTX_cleanup(ctx);
    free(ctx);
    return dec_msg;
}

uint8_t* sign(const char* keypath, const uint8_t* payload, const size_t plen, size_t* slen){

    FILE* ckeyfh;
    EVP_PKEY* ckey=NULL;
    EVP_PKEY_CTX* sigctx;
    uint8_t *sig;

    // Load signing key
    ckeyfh = fopen(keypath,"r");
    if(!ckeyfh)
    {
        fprintf(stderr, "%s: Cannot open the key file\n", __func__);
        sig = NULL;
        goto exit_sign;
    }
    ckey = PEM_read_PrivateKey(ckeyfh, &ckey, NULL, NULL);
    if(!ckey){
        fprintf(stderr,"Cannot read signing key from file %s\n", keypath);
        fclose(ckeyfh);
        sig = NULL;
        goto exit_sign;
    }

    // create signing context
    sigctx = EVP_PKEY_CTX_new(ckey, NULL);
    if (!sigctx){
        fprintf(stderr,"Cannot create a signing context\n");
        fclose(ckeyfh);
        sig = NULL;
        EVP_PKEY_free(ckey);
        goto exit_sign;
    }
    if (EVP_PKEY_sign_init(sigctx) <= 0){
        fprintf(stderr,"Cannot inizialize a signing context\n");
        sig = NULL;
        goto cleanup_sign;
    }

    // Ask the maximum signature size that will result in signing the payload
    if (EVP_PKEY_sign(sigctx, NULL, slen, payload, plen ) <= 0)
    {
        fprintf(stderr, "%s: Cannot get signature size\n", __func__);
        sig = NULL;
        goto cleanup_sign;
    }

    sig = malloc(*slen);
    if(!sig){
        fprintf(stderr,"Out of memory\n");
        goto cleanup_sign;
    }

    // Do the real signature
    if (EVP_PKEY_sign(sigctx, sig, slen, payload, plen) <= 0){
        ERR_load_crypto_strings();
        fprintf(stderr,"Signing operation failed\n");
        printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
        ERR_free_strings();
        sig = NULL;
    }

cleanup_sign:
    fclose(ckeyfh);
    EVP_PKEY_CTX_free(sigctx);
    EVP_PKEY_free(ckey);

exit_sign:
    return sig;
}

int verify(const char* keypath, BIGNUM* nonce, const uint8_t* sig, size_t slen){
    // Nonce
    uint8_t* N;
    size_t Nlen;

    // Context and key
    EVP_PKEY_CTX *verctx;
    FILE* vkeyfh;
    EVP_PKEY *vkey=NULL;

    // Return codes and errors
    int err_code, ret_val;
    unsigned long vererr;

    /*
     * Open the public key of the client for verification
     */
    vkeyfh = fopen(keypath,"r");
    if(!vkeyfh)
    {
        fprintf(stderr, "%s: Cannot open the key file\n", __func__);
        ret_val = 0;
        goto exit_verify;
    }
    vkey = PEM_read_PUBKEY(vkeyfh, &vkey, NULL, NULL);
    if(!vkey){
        fprintf(stderr,"Cannot read verification key from file %s\n", keypath);
        ret_val = 0;
        fclose(vkeyfh);
        goto exit_verify;
    }

    verctx = EVP_PKEY_CTX_new(vkey, NULL);
    if (!verctx){
        fprintf(stderr,"Cannot create a verify context\n");
        ret_val = 0;
        fclose(vkeyfh);
        EVP_PKEY_free(vkey);
        goto exit_verify;
    }

    if (EVP_PKEY_verify_init(verctx) <= 0){
        fprintf(stderr,"Cannot initialize a verify context\n");
        ret_val = 0;
        goto cleanup_verify;
    }

    /*
     * Convert the nonce in a string so that it can be verified
     */
    N = malloc(BN_num_bytes(nonce));
    if (N == NULL)
    {
        fprintf(stderr, "%s: Out of memory\n", __func__);
        ret_val = 0;
        goto cleanup_verify;
    }
    Nlen = BN_bn2bin(nonce, N);

    /* Perform actual verify operation */
    err_code = EVP_PKEY_verify(verctx, sig, slen, N, Nlen);
    if( err_code != 1 ){
        ERR_load_crypto_strings();
        vererr = ERR_get_error();
        fprintf(stderr,"The verify operation on the nonce has failed with code %lu. RET=%d\n",vererr,err_code);
        ERR_free_strings();
        ret_val = 0;
    }
    free(N);
    ret_val = 1;

cleanup_verify:
    EVP_PKEY_CTX_free(verctx);
    EVP_PKEY_free(vkey);
    fclose(vkeyfh);

exit_verify:
    return ret_val;
}

uint8_t*
generate_random_aes_iv (size_t *iv_len)
{
    uint8_t *buffer, buf_len, i;

    // Input error checking
    if (iv_len == NULL)
    {
        fprintf(stderr, "%s: invalid parameter value\n", __func__);
        buffer = NULL;
        goto exit_generate_random_aes_iv;
    }

    // Allocate the buffer
    buf_len = EVP_CIPHER_iv_length(EVP_aes_256_cbc());
    buffer = malloc(buf_len);
    if (buffer == NULL)
    {
        fprintf(stderr, "Error: out of memory\n");
        buffer = NULL;
        *iv_len = 0;
        goto exit_generate_random_aes_iv;
    }

    // Fill the buffer with random content, this increases the entropy for generating the IV
    srand(time(NULL));
    for (i = 0; i < buf_len; i ++)
    {
        buffer[i] = (uint8_t) random();
    }

    // Generate the criptographically strong IV (according to OPENSSL)
    if (RAND_bytes(buffer, buf_len) < 1)
    {
        fprintf(stderr, "Error generating criptographically strong random number\n");
        free(buffer);
        buffer = NULL;
        *iv_len = 0;
    }
    *iv_len = buf_len;
exit_generate_random_aes_iv:
    return buffer;
}

uint8_t*
do_sha256_digest (uint8_t* msg, size_t msg_len)
{
    uint8_t *dig;
    unsigned int dig_len;
    EVP_MD_CTX *ctx;

    if (msg == NULL || msg_len == 0)
    {
        fprintf(stderr, "%s: invalid parameter value\n", __func__);
        dig = NULL;
        goto exit_do_sha256_digest;
    }
    dig = malloc(EVP_MD_size(EVP_sha256()));
    if (dig == NULL)
    {
        fprintf(stderr, "Error allocating memory for the digest\n");
        goto exit_do_sha256_digest;
    }

    // Do the hashing of the msg
    ctx = EVP_MD_CTX_create();
    if (EVP_DigestInit(ctx, EVP_sha256()) != 1)
    {
        fprintf(stderr, "Error initializing digest algorithm\n");
        free(dig);
        dig = NULL;
        goto cleanup_do_sha256_digest;
    }
    if (EVP_DigestUpdate(ctx, msg, msg_len) != 1)
    {
        fprintf(stderr, "Error during the hashing of the message\n");
        free(dig);
        dig = NULL;
        goto cleanup_do_sha256_digest;
    }
    if (EVP_DigestFinal(ctx, dig, &dig_len) != 1)
    {
        fprintf(stderr, "Error finalizing the digest\n");
        free(dig);
        dig = NULL;
        goto cleanup_do_sha256_digest;
    }

    // Check if the size is correct
    if (dig_len != EVP_MD_size(EVP_sha256()))
    {
        fprintf(stderr, "Error, the digest's length is less than expected\n");
        free(dig);
        dig = NULL;
    }

cleanup_do_sha256_digest:
    EVP_MD_CTX_cleanup(ctx);
    free(ctx);

exit_do_sha256_digest:
    return dig;
}

uint8_t* encrypt(const char* keypath, const uint8_t* p, const size_t plen, size_t* clen, uint8_t** iv, size_t* ivlen, uint8_t** ek, size_t* ekl){
    // Context and key
    FILE* ckeyfh;
    EVP_PKEY *ckey=NULL;

    // Return codes and errors
    unsigned long encerr;

    /* The buffer with the ciphertext */
    uint8_t* c;

    /* Variables  related to the symmetric enc of the envelope */
    EVP_CIPHER_CTX *encctx = NULL;
    const EVP_CIPHER* type = EVP_aes_256_cbc(); // Type of encryption
    int outl, outf;
	int eklint;

    /*
     * Open a public key for encryption
     */
    ckeyfh = fopen(keypath,"r");
    if (!ckeyfh)
    {
        fprintf(stderr, "%s: Cannot open key file\n", __func__);
        c = NULL;
        goto exit_encrypt;
    }
    ckey = PEM_read_PUBKEY(ckeyfh, &ckey, NULL, NULL);
    if (!ckey){
        fprintf(stderr,"Cannot read encryption key from file %s\n", keypath);
        fclose(ckeyfh);
        c = NULL;
        goto exit_encrypt;
    }

    /* EVP_Seal* need a CIPHER_CTX */
    encctx = malloc(sizeof(EVP_CIPHER_CTX));
    if (encctx == NULL)
    {
        fprintf(stderr, "%s: Out of memory\n", __func__);
        fclose(ckeyfh);
        EVP_PKEY_free(ckey);
        c = NULL;
        goto exit_encrypt;
    }

    EVP_CIPHER_CTX_init(encctx);
    if (!encctx){
        fprintf(stderr,"Cannot inizialize an encryption context\n");
        c = NULL;
        goto cleanup_encrypt;
    }

    /* Start the encryption process - generate IV and key */
    *ivlen = EVP_CIPHER_iv_length(type);
    *iv = malloc(*ivlen);
    if (iv == NULL)
    {
        fprintf(stderr, "%s: Out of memory allocating of IV\n", __func__);
        c = NULL;
        goto cleanup_encrypt;
    }
    *ek = malloc(EVP_PKEY_size(ckey));
    if (*ek == NULL)
    {
        fprintf(stderr, "%s: Out of memory allocating ek\n", __func__);
        free(iv);
        c = NULL;
        goto cleanup_encrypt;
    }
    c = malloc(plen + EVP_CIPHER_block_size(type));
    if (c == NULL)
    {
        fprintf(stderr, "%s: Out of memory for \n", __func__);
        free(iv);
        free(*ek);
        goto cleanup_encrypt;
    }

    if (EVP_SealInit(encctx, type, ek, &eklint, *iv, &ckey, 1) != 1){
        ERR_load_crypto_strings();
        encerr = ERR_get_error();
        fprintf(stderr,"Encrypt failed\n");
        printf("%s\n", ERR_error_string(encerr, NULL));
        ERR_free_strings();
        free(iv);
        free(*ek);
        free(c);
        c = NULL;
        goto cleanup_encrypt;
    }
	*ekl = eklint;

    /* Encrypt data, then finalize */
    if (EVP_SealUpdate(encctx, c, &outl, p, plen) != 1){
        ERR_load_crypto_strings();
        encerr = ERR_get_error();
        fprintf(stderr,"Encrypt failed\n");
        printf("%s\n", ERR_error_string(encerr, NULL));
        ERR_free_strings();
        free(iv);
        free(*ek);
        free(c);
        c = NULL;
        goto cleanup_encrypt;
    }
    if (EVP_SealFinal(encctx, &c[outl], &outf) != 1){
        ERR_load_crypto_strings();
        encerr = ERR_get_error();
        fprintf(stderr,"Encrypt failed\n");
        printf("%s\n", ERR_error_string(encerr, NULL));
        ERR_free_strings();
        free(c);
        c = NULL;
        outl = outf = 0;
    }

    *clen = outl + outf;

    cleanup_encrypt:
    EVP_CIPHER_CTX_cleanup(encctx);
    free(encctx);
    fclose(ckeyfh);
    EVP_PKEY_free(ckey);

    exit_encrypt:
    return c;
}


uint8_t* decrypt(const char* keypath, const uint8_t* c, const size_t clen, size_t* plen, uint8_t* iv, uint8_t* ek, size_t ekl){
    // Context and key
    EVP_CIPHER_CTX *decctx;
    FILE* dkeyfh;
    EVP_PKEY *dkey=NULL;

    // Return codes and errors
    unsigned long decerr;

    /* The buffer with the plaintext */
    uint8_t* p;

    /* envelope related */
    int outl;
	int plenint;
    const EVP_CIPHER* type = EVP_aes_256_cbc();

    /*
     * Open a private key for decryption
     */
    dkeyfh = fopen(keypath,"r");
    if (!dkeyfh)
    {
        fprintf(stderr, "%s: Cannot open key file\n", __func__);
        p = NULL;
        goto exit_decrypt;
    }
    dkey = PEM_read_PrivateKey(dkeyfh, &dkey, NULL, NULL);
    if (!dkey){
        fprintf(stderr,"Cannot read decryption key from file %s\n", keypath);
        p = NULL;
        fclose(dkeyfh);
        goto exit_decrypt;
    }

    decctx = malloc(sizeof(EVP_CIPHER_CTX));
    if (decctx == NULL)
    {
        fprintf(stderr, "%s: Out of memory\n", __func__);
        p = NULL;
        fclose(dkeyfh);
        goto exit_decrypt;
    }
    EVP_CIPHER_CTX_init(decctx);
    if (!decctx){
        fprintf(stderr,"Cannot initialize an decryption context\n");
        p = NULL;
        goto cleanup_decrypt;
    }

    p = malloc(clen + EVP_CIPHER_block_size(type));
    if (p == NULL)
    {
        fprintf(stderr,"%s: Out of memory\n", __func__);
        goto cleanup_decrypt;
    }

    if (EVP_OpenInit(decctx, type, ek, ekl, iv, dkey) != 1){
        ERR_load_crypto_strings();
        decerr = ERR_get_error();
        fprintf(stderr,"Decrypt failed\n");
        printf("%s\n", ERR_error_string(decerr, NULL));
        ERR_free_strings();
        p = NULL;
        goto cleanup_decrypt;
    }

    if (EVP_OpenUpdate( decctx, p, &plenint, c, clen) != 1){
        ERR_load_crypto_strings();
        decerr = ERR_get_error();
        fprintf(stderr,"Decrypt failed\n");
        printf("%s\n", ERR_error_string(decerr, NULL));
        ERR_free_strings();
        p = NULL;
        goto cleanup_decrypt;
    }

    if(EVP_OpenFinal(decctx, p, &outl) != 1){
        ERR_load_crypto_strings();
        decerr = ERR_get_error();
        fprintf(stderr,"Decrypt failed\n");
        printf("%s\n", ERR_error_string(decerr, NULL));
        ERR_free_strings();
        p = NULL;
    }
    *plen = outl + plenint;

    cleanup_decrypt:
    EVP_CIPHER_CTX_cleanup(decctx);
    free(decctx);
    EVP_PKEY_free(dkey);

    exit_decrypt:
    return p;
}
