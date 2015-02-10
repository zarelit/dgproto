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

	// M3 and M4
	msg_data m3, m4;

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
		printf("M1 is %lu bytes long\n", m1.data_len);
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
		printf("M2 is %lu bytes long\n", m2.data_len);
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

	say("");
	doing("Compare IVs");
	if(memcmp(IV, IV_ofA, 16) != 0){
		say("5. Test failed. IVs are different.");
		exit(EXIT_FAILURE);
	} else {
		say("5. Test ok. IVs are the same.");
		dump("IV", IV, 16);
	}

	say("");
	doing("Client sends M3 to server who verifies it");
	m3.data = create_m3(&(m3.data_len), A_key, Nb_ofA, IV_ofA);
	if( m3.data == NULL){
		say("6. Test failed. Cannot create M3");
		exit(EXIT_FAILURE);
	}else{
		say("6. Test ok. M3 generated succesfully");
		printf("M3 is %lu bytes long\n", m3.data_len);
	}

	test = verifymessage_m3(m3.data, m3.data_len, Nb, B_key, IV);
	if(test == 0){
		say("7. Test failed. M3 is not verified correctly");
		exit(EXIT_FAILURE);
	} else {
		say("7. Test ok. M3 is verified correctly");
	}

	say("");
	doing("Server sends M4 to client who verifies it");
	m4.data = create_m4(&(m4.data_len), B_key, Na_ofB, IV);
	if( m4.data == NULL){
		say("8. Test failed. Cannot create M4");
		exit(EXIT_FAILURE);
	}else{
		say("8. Test ok. M4 generated succesfully");
		printf("M4 is %lu bytes long\n", m4.data_len);
	}

	test = verifymessage_m4(m4.data, m4.data_len, Na, A_key, IV_ofA);
	if(test == 0){
		say("9. Test failed. M4 is not verified correctly");
		exit(EXIT_FAILURE);
	} else {
		say("9. Test ok. M4 is verified correctly");
	}
		
	return 0;
}
