#include "sha1.h"

int main(uint8_t argc, unsigned char *argv[]) {
	uint64_t m_len;
	uint32_t hash[5];
	printf("\n========================================================\n");
	printf("********** Secure Hash Algorithm 128 (SHA-1) ***********");
	printf("\n========================================================\n");
	if(argc > 1) {
		for(uint8_t i = 1; i < argc; i++) {
			printf("Input %d : %s", i, argv[i]);
			m_len = strlen(argv[i]);
			SHA1(argv[i], m_len, hash);
			printf("\nSHA1 Hash : ");
		        for(uint8_t j = 0; j < 5; j++)
       		        	printf("%08x ", hash[j]);
			printf("\n========================================================\n");
		}
	}
	else
		printf("************ Error! No valid input to Hash *************");
	printf("\n========================================================\n");
	printf("*********************** Thank You **********************");
	printf("\n========================================================\n");
	return 0;
}

