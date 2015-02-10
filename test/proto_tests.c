#include "../include/common.h"
#include "../include/protocol.h"
#include "../include/utils.h"

int main(){

	// M1
	BIGNUM* Na;
	BIGNUM* Na_ofB;
	msg_data m1;

	// M2
	BIGNUM* Nb;
	BIGNUM* Nb_ofA;
	msg_data m2;
	uint8_t* IV=NULL;
	uint8_t* IV_ofA=NULL;

	// Key generation
	uint8_t *A_key, *B_key; 

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

	say("");
	doing("Server generates Nb");
	Nb = generate_random_nonce();

	doing("Server sends M2");
	m2.data = create_m2 (&(m2.data_len), 'B', Nb, Na, &IV );
	if( m2.data == NULL){
		say("2. Test failed. Cannot create M2");
		exit(EXIT_FAILURE);
	}else{
		say("2. Test ok. M2 generated succesfully");
		//dump("M1",m1.data,m1.data_len);	
	}

	doing("Client verifies M2 and extracts Nb and IV from it");
	test = verifymessage_m2 (m2.data, m2.data_len, Na, &Nb_ofA, &IV_ofA);
	if(test == 0){
		say("3. Test failed. M2 is not verified correctly");
		exit(EXIT_FAILURE);
	} else {
		say("3. Test ok. M2 is verified correctly");
	}

	say("");
	doing("Creating keys");
	A_key = generate_key(Na, Nb_ofA);	
	B_key = generate_key(Na_ofB, Nb);	
	if(memcmp(A_key, B_key, KEY_LEN/8) != 0){
		say("4. Test failed. Keys are different.");
		exit(EXIT_FAILURE);
	} else {
		say("4. Test ok. Keys are the same.");
		dump("Key", A_key, KEY_LEN/8);
	}

	return 0;
}
