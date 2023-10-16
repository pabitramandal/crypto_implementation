#include "aes.h"

int main() {
	uint8_t i, j, choice;

	// Key for AES-128
//	uint8_t key[Nk << 2] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

	// Key for AES-192
	//uint8_t key[Nk << 2] = {
	//	0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 
	//	0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};

	// Key for AES-256
	uint8_t key[Nk << 2] = {
		0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

	uint8_t IV[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

	uint8_t init_ctr[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};

	uint8_t msg[] = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
		0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
		0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};

//	uint8_t msg[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

	uint64_t m_len = sizeof(msg);
	uint8_t b_count = (m_len >> 4) + 1;
	uint64_t p_mlen = b_count << 4;
	uint8_t p_msg[b_count << 4], c_text[b_count << 4], d_text[b_count << 4];

	aes_padd(msg, m_len, p_msg, p_mlen);
	
	printf("\n=========================================================\n");
	printf("*********** Advanced Encryption Standard (AES) **********");
	printf("\n=========================================================\n");
	printf("Padded Message : ");
	for(i = 0; i < b_count; i++) {
		printf("\nBlock %d : ", i);
		for(j = 0; j < 16; j ++)
			printf("%2.2x ", p_msg[(i << 4) + j]);
	}
	
	/*
	printf("\n=========================================================\n");
	printf("Encryption Schemes :");
	printf("\n[1] : AES-128");
	printf("\n[2] : AES-192");
	printf("\n[3] : AES-256");
	printf("\n\nSelect the Encryption Scheme : ");
	scanf("%hhd", &choice);
	printf("=========================================================\n");
	switch(choice) {
		case 1: 
			printf("Chosen Encryption Scheme : AES-128");
			Nk = 4; Nr = 10;
			uint8_t key[Nk << 2] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
			break;
		case 2:
			printf("Chosen Encryption Scheme : AES-192");
			Nk = 6; Nr = 12;
			uint8_t key[Nk << 2] = {
				0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
				0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
			break;
		case 3:
			printf("Chosen Encryption Scheme : AES-256");
			Nk = 8; Nr = 14;
			uint8_t key[Nk << 2] = {
				0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
				0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
		default:
			printf("******************** INVALID CHOICE! ********************");
			printf("\n=========================================================\n");
			exit(1);
	}*/

	printf("\n=========================================================\n");
	printf("Block Cipher Modes of Operations :");
	printf("\n[1] : The Electronic Codebook (ECB) Mode");
	printf("\n[2] : The Cipher Block Chaining (CBC) Mode");
	printf("\n[3] : The Cipher Feedback (CFB) Mode");
	printf("\n[4] : The Output Feedback (OFB) Mode");
	printf("\n[5] : The Output Feedback (CTR)");
	printf("\n\nSelect the Mode of Operations : ");
	scanf("%hhd", &choice);
	printf("=========================================================\n");
	switch(choice) {
		case 1:
			printf("Chosen Mode of Operation : AES-ECB Mode");
			ecb_encrypt(key, p_msg, c_text, b_count);
			ecb_decrypt(key, c_text, d_text, b_count);
			break;
		case 2:
			printf("Chosen Mode of Operation : AES-CBC Mode");
			cbc_encrypt(key, IV, p_msg, c_text, b_count);
			cbc_decrypt(key, IV, c_text, d_text, b_count);
			break;
		case 3:
			printf("Chosen Mode of Operation : AES-CFB Mode");
			printf("\n=========================================================\n");
			printf("----------------- NOT IMPLEMENTED YET -------------------");
			printf("\n=========================================================\n");
			exit(1);
		case 4:
			printf("Chosen Mode of Operation : AES-OFB Mode");
			ofb_encrypt(key, IV, p_msg, c_text, b_count);
			ofb_encrypt(key, IV, c_text, d_text, b_count);
			break;
		case 5:
			printf("Chosen Mode of Operation : AES-CTR Mode");
			ctr_encrypt(key, init_ctr, p_msg, c_text, b_count);
			ctr_encrypt(key, init_ctr, c_text, d_text, b_count);
			break;
		default:
			printf("******************** INVALID CHOICE! ********************");
			printf("\n=========================================================\n");
			exit(1);
	}
	printf("\n=========================================================\n");
	printf("Cipher Text : ");
	for(i = 0; i < b_count; i++) {
		printf("\nBlock %d : ", i);
		for(j = 0; j < 16; j++)
			printf("%2.2x ", c_text[(i << 4) + j]);
	}
	printf("\n=========================================================\n");

	printf("Decrypted Text : ");
	for(i = 0; i < b_count; i++) {
		printf("\nBlock %d : ", i);
		for(j = 0; j < 16; j++)
			printf("%2.2x ", d_text[(i << 4) + j]);
	}
	printf("\n=========================================================\n");
	printf("*********************** Thank You ***********************");
	printf("\n=========================================================\n");
	return 0;
}

