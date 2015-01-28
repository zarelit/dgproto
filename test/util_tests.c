#include "../include/common.h"
#include "../include/utils.h"

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

