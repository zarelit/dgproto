#include "../include/common.h"
#include "../include/protocol.h"
#include "../include/utils.h"

int main(){

	BIGNUM* Na;
	BIGNUM* Na_ofB;
	msg_data m1;

	int test;

	doing("Client generates Na");
	Na = generate_random_nonce();

	doing("Client sends M1");
	m1.data = create_m1 (&(m1.data_len), 'A', Na);
	if( m1.data == NULL){
		say("1. Test failed. Cannot create M1");
		exit(EXIT_FAILURE);
	}else{
		say("1. Test ok. M1 generated succesfully");
		//dump("M1",m1.data,m1.data_len);	
	}

	say("");
	doing("Server verifies M1 and extracts Na from it");
	test = verifymessage_m1 (m1.data, m1.data_len, &Na_ofB);
	if(test != 1){
		say("2. Test failed. M1 is not verified correctly");
		exit(EXIT_FAILURE);
	} else {
		say("2. Test ok. M1 is verified correctly");
	}

	return 0;
}
