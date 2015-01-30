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
	uint8_t* sig;
	size_t siglen;

	BIGNUM* No; // A Nonce
	uint8_t* Noval;
	int Nolen;

	doing("Generate a nonce");
	No = generate_random_nonce();
	Noval = malloc(BN_num_bytes(No));
    Nolen = BN_bn2bin(No, Noval);
	dump("Generated nonce",Noval,Nolen);

	doing("Sign nonce");
	sig = sign("keys/client.pem",Noval,Nolen,&siglen);
	dump("Nonce signature", sig, siglen);


	return 0;
}

