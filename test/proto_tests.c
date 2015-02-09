#include "../include/common.h"
#include "../include/protocol.h"
#include "../include/utils.h"

int main(){
	BIGNUM* Na;
	uint8_t* m1;
	size_t m1_len;

	Na = generate_random_nonce();
	m1 = create_m1 (&m1_len, 'A', Na);
	if( m1 == NULL) exit(EXIT_FAILURE);
	dump("M1",m1,m1_len);	

	return 0;
}
