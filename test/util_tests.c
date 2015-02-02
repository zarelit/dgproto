#include "../include/common.h"
#include "../include/utils.h"
#include "../include/protocol.h"

#define say(yeah) printf("%s\n",yeah)
#define dump(name, quantity, length) printf("%s length: %d\n", name, length);\
									 printf("%s dump:\n", name);\
									 hexdump(stdout,quantity, length);\
									 printf("\n");
#define doing(something) printf("** "); say(something);

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
	dump("Nonce",Noval,Nolen);

	doing("Sign nonce");
	sig = sign("keys/client.pem",Noval,Nolen,&siglen);
	dump("Nonce signature", sig, siglen);

	doing("Verify a correct signature");
	ret = verify("keys/client.pub.pem", No, sig, siglen);
	if(!ret){
		say("Verification failed.");
	}else{
		say("Verification successful");
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
	return 0;
}

