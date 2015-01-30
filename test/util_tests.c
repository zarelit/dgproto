#include "../include/common.h"
#include "../include/utils.h"

#define say(yeah) printf("%s\n",yeah)
#define dump(name, quantity, length) printf("%s length: %d\n", name, length);\
									 printf("%s dump:\n", name);\
									 hexdump(stdout,quantity, length);
int main(){
	char tbs[]="Stringa da firmare";
	int tbslen=strlen(tbs);
	uint8_t* sig;
	size_t siglen;

	printf("Testing sign functions:\n");
	printf("String: %s, length: %d, hexdump: ",tbs, tbslen);
	hexdump(stdout,tbs,tbslen);
	printf("\n");
	sig = sign("keys/client.pem",tbs,tbslen,&siglen);
	printf("Signature length: %d, hexdump: ",siglen);
	hexdump(stdout,sig,siglen);
	printf("\n");


	return 0;
}

