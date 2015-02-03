#include "../include/common.h"
#include "../include/utils.h"
#include "../include/protocol.h"

#define say(yeah) printf("%s\n",yeah)
#define dump(name, quantity, length) printf("%s length: %d\n", name, length);\
									 printf("%s dump:\n", name);\
									 hexdump(stdout,quantity, length);\
									 printf("\n");
#define doing(something) printf("** "); say(something);

int
test_conc_msgs (void)
{
    const uint8_t el_num = 3, num = 0xFF;
    msg_data msgs[el_num];
    uint8_t *buffer, ret_val, i, j;
    size_t buf_len, test_len;

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
    printf("test_len = %d\n", (int)test_len);
    dump("Buffer", buffer, (int) buf_len);
    ret_val = 0;
    if (buffer != NULL && buf_len == test_len)
    {
        ret_val = 1;
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
        ret = test_conc_msgs();
        if (ret == 0)
        {
            say("3. test_conc_msgs(): test failed.");
        }
        else
        {
            say("3. test_conc_msgs(): test succeded.");
        }

	free(sig);
	free(noise);
	return 0;
}

