#include "../include/common.h"
#include "../include/utils.h"
#include "../include/protocol.h"

int
test_do_aes256_crypt (void)
{
//     uint8_t ret_val = 0;
//     const char *test_str = "asd lol";
//     const char *test_enc = "a9b851f862f26a81b7ef891436994f82";
}

int
test_do_sha256_digest (void)
{
    uint8_t *test_str = "asd lol";
    uint8_t test_dig[] = {0xf8,0xe5,0xa4,0x50,0xdb,0x8f,0x2c,0x0f,
                          0xfb,0x86,0x7d,0x22,0x6b,0x76,0x9b,0xf1,
                          0x37,0x85,0x45,0xe2,0x62,0x71,0xa9,0x50,
                          0xa7,0xb1,0x93,0x53,0x40,0xcc,0x39,0x4a};
    uint8_t *dig = NULL, ret_val, i;
    BIGNUM *test_dig_bn;
    size_t test_str_len = strlen(test_str);

    test_dig_bn = BN_new();
    test_dig_bn = BN_bin2bn(&test_dig[0], (256 >> 3), NULL);
    BN_print_fp(stderr, test_dig_bn);

    ret_val = 1;
    dig = do_sha256_digest(test_str, test_str_len);
    if (dig == NULL)
    {
        fprintf(stderr, "%s: dig is NULL\n", __func__);
        ret_val = 0;
        goto exit_test_do_sha256_digest;
    }
    if (memcmp(dig, test_dig, (256 >> 3)) != 0)
    {
        fprintf(stderr, "%s: dig differs from test_dig\n", __func__);
        fprintf(stderr, "    test_dig = ");
        for (i = 0; i < (256 >> 3); i ++)
        {
            fprintf(stderr,"%02hhX",test_dig[i]);
        }
        fprintf(stderr, "\n    dig = ");
        for (i = 0; i < (256 >> 3); i ++)
        {
            fprintf(stderr,"%02hhX",dig[i]);
        }
        ret_val = 0;
    }
    free(dig);
    BN_clear_free(test_dig_bn);
    free(test_dig);
exit_test_do_sha256_digest:
    return ret_val;
}

int
test_conc_msgs (void)
{
    const uint8_t el_num = 3, num = 0x00;
    msg_data msgs[el_num];
    uint8_t *buffer, ret_val, i, j;
    size_t buf_len, test_len;

    // Create the messages that will be concatenated
    test_len = 0;
    for (i = 0; i < el_num; i ++)
    {
        msgs[i].data = calloc(el_num + i, sizeof(uint8_t) * (el_num + i));
        msgs[i].data_len = el_num + i;
        test_len += el_num + i;
        for (j = 0; j < (el_num + i); j ++)
        {
            msgs[i].data[j] = num - j;
        }
        printf("msg_data[%d].data\n", i);
        hexdump(stdout, msgs[i].data, el_num + i);
        printf("\n");
    }

    // Concatenate and verify if all goes as expected
    buffer = conc_msgs(&buf_len, el_num, msgs[0], msgs[1], msgs[2]);
    dump("conc_msgs buffer", buffer, (int) buf_len);
    ret_val = 0;
    if (buffer != NULL && buf_len == test_len)
    {
        ret_val = 1;
    }
    for (i = 0; i < el_num; i ++)
    {
        free(msgs[i].data);
    }
    free(buffer);
    return ret_val;
}

int
test_extr_msgs (void)
{
    const uint8_t el_num = 3, num = 0x00;
    msg_data msgs[el_num];
    uint8_t *buffer, ret_val, i, j;
    size_t buf_len, test_len;

    // Create the buffer which contains concatenated messages
    test_len = 0;
    for (i = 0; i < el_num; i ++)
    {
        msgs[i].data = calloc(el_num + i, sizeof(uint8_t) * (el_num + i));
        msgs[i].data_len = el_num + i;
        test_len += el_num + i;
        for (j = 0; j < (el_num + i); j ++)
        {
            msgs[i].data[j] = num - j;
        }
        printf("msg_data[%d].data\n", i);
        hexdump(stdout, msgs[i].data, el_num + i);
        printf("\n");
    }
    buffer = conc_msgs(&buf_len, el_num, msgs[0], msgs[1], msgs[2]);

    // Create the messages which have to be extracted from buffer
    for (i = 0; i < el_num; i ++)
    {
        msgs[i].data = NULL;
        msgs[i].data_len = el_num + i;
    }
    dump("extr_msgs buffer", buffer,(int) buf_len);

    // Extract the messages
    ret_val = extr_msgs(buffer, el_num, &msgs[0], &msgs[1], &msgs[2]);
    for (i = 0; i < el_num; i ++)
    {
        printf("msg_data[%d].data\n", i);
        hexdump(stdout, msgs[i].data, el_num + i);
        printf("\n");
    }
    free(buffer);
    for (i = 0; i < el_num; i ++)
    {
        free(msgs[i].data);
    }
    return ret_val;
}

int main(){
	// The test nonce
	BIGNUM* No;
	uint8_t* Noval;
	int Nolen;

	// The test signature
	uint8_t* sig;
	uint8_t* noise;
	size_t siglen;

	// Test buffers for encrypt/decrypt
	uint8_t* plain;
	size_t plen;
	uint8_t* cipher;
	size_t clen;

	// Auxiliary variables
	int ret, i;

	doing("Generate a nonce");
	No = generate_random_nonce();
	Noval = malloc(BN_num_bytes(No));
    Nolen = BN_bn2bin(No, Noval);
	// dump("Nonce",Noval,Nolen);
	printf("Nonce is %d bytes long\n",Nolen);

	doing("Sign nonce");
	sig = sign("keys/client.pem",Noval,Nolen,&siglen);
	// dump("Nonce signature", sig, siglen);
	printf("Nonce signature is %ld bytes long\n",siglen);

	doing("Verify a correct signature");
	ret = verify("keys/client.pub.pem", No, sig, siglen);
	if(!ret){
		say("1. Test fail. Verification failed.");
	}else{
		say("1. Test ok. Verification successful.");
	}

	doing("Verify the signature with some random bits flipped");
	noise = malloc(siglen);
	if(RAND_bytes(noise,siglen)==1){
		for(i=0; i<siglen; i++){
			sig[i] ^= noise[i];
		}
	}

	ret = verify("keys/client.pub.pem", No, sig, siglen);
	if(!ret){
		say("2. Test ok. Verification failed.");
	}else{
		say("2. Test fail. Verification successful.");
	}
	free(sig);
	free(noise);

    if (test_conc_msgs() == 0)
    {
        say("3. test_conc_msgs(): test failed.");
    }
    else
    {
        say("3. test_conc_msgs(): test succeded.");
    }
    if (test_extr_msgs() == 0)
    {
        say("4. test_extr_msgs(): test failed.");
    }
    else
    {
        say("4. test_extr_msgs(): test succeded.");
    }

	doing("Encrypt the nonce");
	cipher = encrypt("keys/client.pub.pem",Noval,Nolen,&clen);
	// dump("Ciphertext",cipher,clen);
	doing("Decrypting the nonce");
	plain = decrypt("keys/client.pem",cipher,clen,&plen);
	// dump("Plaintext",plain,plen);

	doing("Verify that we have the same plaintext after decryption");
	ret = 1;
	if(plen != Nolen) ret=0;
	else if(memcmp(plain,Noval,Nolen)) ret=0;

	if(ret) say("5. Decryption test ok.");
	else say("5. Decryption test fail.");

	return 0;
}

