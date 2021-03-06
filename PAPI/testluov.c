#include <stdio.h>
#include <stdlib.h>
#include <papi.h>
#include <time.h>
#include <string.h>

#include "parameters.h"
#include "KeccakHash.c"
#include "KeccakSpongeWidth1600.c"
#include "KeccakP-1600-opt64.c"
#include "F16Field.h"
#include "F32Field.h"
#include "F48Field.h"
#include "F64Field.h"
#include "F80Field.h"

#include "LUOV.h"
#include "LUOV.c"
#include "api.h"
#include "AES.c"
#include "F8Field.c"

#include "hpc.h"

#define NUMBER_OF_KEYPAIRS 10      /* Number of keypairs that is generated during test */
#define SIGNATURES_PER_KEYPAIR 1  /* Number of times each keypair is used to sign a random document, and verify the signature */

//used for timing stuff
static inline
uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}
#define TIC printf("\n"); uint64_t cl = rdtsc();
#define TOC(A) printf("%s cycles = %llu \n",#A ,rdtsc() - cl); cl = rdtsc();
/*
	Tests the execution of the keypair generation, signature generation and signature verification algorithms and prints timing results
*/
int main(void)
{
	int i, j, k;
	int message_size = 100;
	
	/*---------Define PAPI Variable----------*/
	int EventSet;
	long_long values[5], values1[5], values2[5], values3[5],save[5];


	for(i=0;i<5;i++)
	{
		save[i] = 0;
	}


	/*---------Define PAPI Variable----------*/
	
	
	unsigned long long smlen;
	unsigned char m[message_size];
	unsigned char m2[message_size];
	unsigned char *pk = malloc(sizeof(unsigned char[CRYPTO_PUBLICKEYBYTES]));
	unsigned char *sk = malloc(sizeof(unsigned char[CRYPTO_SECRETKEYBYTES]));
	unsigned char *sm = malloc(sizeof(unsigned char[message_size + CRYPTO_BYTES]));
	clock_t cl;

	/*---------Initialize the PAPI library and Create EventSet----------*/

	if (PAPI_library_init(PAPI_VER_CURRENT) != PAPI_VER_CURRENT)

	exit(-1);

	EventSet = PAPI_NULL;

	if (PAPI_create_eventset(&EventSet) != PAPI_OK)

	exit(-1);
	/*---------Initialize the PAPI library and Create EventSet----------*/

	/*------------Add Event----------*/

	if (PAPI_add_event(EventSet, PAPI_TOT_INS) != PAPI_OK)

	exit(-1);

	if (PAPI_add_event(EventSet, PAPI_L1_DCM) != PAPI_OK)

	exit(-1);

	if (PAPI_add_event(EventSet, PAPI_TOT_CYC) != PAPI_OK)

	exit(-1);
	if (PAPI_add_event(EventSet, PAPI_BR_INS) != PAPI_OK)

	exit(-1);
	if (PAPI_add_event(EventSet, PAPI_BR_NTK) != PAPI_OK)

	exit(-1);


	/*------------Add Event----------*/




	if (PAPI_start(EventSet) != PAPI_OK)

	exit(-1);

//if (PAPI_read(EventSet, values1) != PAPI_OK)

//exit(-1);




	// Print key and signature sizes


	/*
	printf("Public Key takes %d B\n", CRYPTO_PUBLICKEYBYTES );
	printf("Secret Key takes %d B\n", CRYPTO_SECRETKEYBYTES );
	printf("Signature takes %d B\n\n", CRYPTO_BYTES );

	printf("Public Key takes %.2f kB\n", CRYPTO_PUBLICKEYBYTES / 1024.0);
	printf("Secret Key takes %.2f kB\n", CRYPTO_SECRETKEYBYTES / 1024.0);
	printf("Signature takes %.2f kB\n\n", CRYPTO_BYTES / 1024.0);


	*/

	srand((unsigned int) time(NULL));

	float genTime = 0.0;
	float signTime = 0.0;
	float verifyTime = 0.0;
	uint64_t keygen_cyc = 0;
	uint64_t sign_cyc = 0;
	uint64_t verify_cyc = 0;
	uint64_t cycles = 0;


	HPC_START(1);

	for (i = 0; i < NUMBER_OF_KEYPAIRS ; i++) {

		// time key pair generation
		cl = clock();
		cycles = rdtsc();


		//	printf("PAPI TESTING!!!!!!!!\n");		
		//HPC_START TEST
		
		
		crypto_sign_keypair(pk, sk);
		
	

		
		keygen_cyc += rdtsc()-cycles;
		cl = clock() - cl;
		genTime += ((float) cl)/CLOCKS_PER_SEC;

		for (j = 0; j < SIGNATURES_PER_KEYPAIR ; j++) {
			
			// pick a random message to sign
			for (k = 0; k < message_size; k++) {
				m[k] = ((unsigned char) rand());
			}

			// time signing algorithm
			cl = clock();
			cycles = rdtsc();

			


			crypto_sign(sm, &smlen, m, (unsigned long long) message_size, sk);

			
			sign_cyc += rdtsc() - cycles;
			cl = clock() - cl;
			signTime += ((float)cl) / CLOCKS_PER_SEC;

			// time verification algorithm
			cl = clock();
			cycles = rdtsc();

			 
			if (crypto_sign_open(m2, &smlen, sm, smlen, pk) != 0) {
				printf("Verification of signature Failed!\n");
			}

			
			verify_cyc += rdtsc() - cycles;
			cl = clock() - cl;
			verifyTime += ((float)cl) / CLOCKS_PER_SEC;

			// check if recovered message length is correct
			if (smlen != message_size){
				printf("Wrong message size !\n");
			}
			// check if recovered message is correct
			for(k = 0 ; k<message_size ; k++){
				if(m[k]!=m2[k]){
					printf("Wrong message !\n");
					break;
				}
			}
		}

	}
	HPC_END(1); 
		if (PAPI_stop(EventSet, values3) != PAPI_OK)
                                         exit(-1);


		if (PAPI_cleanup_eventset(EventSet) != PAPI_OK)

 		exit(-1);
 						
 		if (PAPI_destroy_eventset(&EventSet) != PAPI_OK)
 							
 		exit(-1);
 							
 		PAPI_shutdown(); 



/* Get value */

//values[0]=values2[0]-values1[0];
//values[1]=values2[1]-values1[1];
//values[2]=values2[2]-values1[2];

printf("High Performance Counters of Complete LUOV are as follows\n");
printf("TOT_INS:%lld\n  L1_DCM: %lld\n TOT_CYC: %lld\n ",save[0], save[1],save[2]);
printf(" Branches: %lld\n Branch-misses: %lld\n\n ",save[3],save[4]);
//printf("TOT_INS:%lld\n  ",save);


/*
	printf("\n");
	printf("Key pair generation took %.4f seconds.\n", genTime / NUMBER_OF_KEYPAIRS);
	printf("Signing took %.4f seconds.\n", (signTime/NUMBER_OF_KEYPAIRS)/SIGNATURES_PER_KEYPAIR );
	printf("Verifying took %.4f seconds.\n\n", (verifyTime / NUMBER_OF_KEYPAIRS) / SIGNATURES_PER_KEYPAIR );

	printf("Key pair generation took %ld cycles.\n", keygen_cyc / NUMBER_OF_KEYPAIRS);
	printf("Signing took %ld cycles.\n", (sign_cyc/NUMBER_OF_KEYPAIRS)/SIGNATURES_PER_KEYPAIR );
	printf("Verifying took %ld cycles.\n\n", (verify_cyc / NUMBER_OF_KEYPAIRS) / SIGNATURES_PER_KEYPAIR );

*/

	free(pk);
	free(sk);
	free(sm);

	return 0;
}
