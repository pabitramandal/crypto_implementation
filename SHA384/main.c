#include "sha384.h"

int main(uint8_t argc, unsigned char *argv[]) {
	uint64_t m_len, hash[8];
	printf("\n==================================================\n");
	printf("******* Secure Hash Algorithm 384 (SHA-2) ********");
	printf("\n==================================================\n");
	if(argc > 1) {
		for(uint8_t i = 1; i < argc; i++) {
			printf("Input %d : %s\n", i, argv[i]);
			m_len = strlen(argv[i]);
			SHA384(argv[i], m_len, hash);
			printf("SHA384 Hash : ");
		        for(uint8_t j = 0; j < 6; j = j + 3)
                		printf("\n%016lx %016lx %016lx", hash[j], hash[j + 1], hash[j + 3]);
			printf("\n==================================================\n");
		}
	}
	else
	printf("********** Error! No valid input to Hash *********");
	printf("\n==================================================\n");
	printf("******************** Thank You *******************");
	printf("\n==================================================\n");
	return 0;
}

