#include<stdio.h>
#include<stdint.h>
#include<string.h>

// Constants for MD5
#define MD5_BLOCK_SIZE 64
#define MD5_DIGEST_SIZE 16

// MD5 Functions
#define F(X, Y, Z) (((X) & (Y)) | ((~X) & (Z)))
#define G(X, Y, Z) (((X) & (Z)) | ((Y) & (~Z)))
#define H(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define I(X, Y, Z) ((Y) ^ ((X) | (~Z)))

// MD5 transformation macros
#define FF(a, b, c, d, x, s, ac) { \
	(a) += F((b), (c), (d)) + (x) + (ac); \
	(a) = (((a) << (s)) | ((a) >> (32 - (s)))); \
	(a) += (b); \
}
#define GG(a, b, c, d, x, s, ac) { \
	(a) += G((b), (c), (d)) + (x) + (ac); \
	(a) = (((a) << (s)) | ((a) >> (32 - (s)))); \
	(a) += (b); \
}
#define HH(a, b, c, d, x, s, ac) { \
	(a) += H((b), (c), (d)) + (x) + (ac); \
	(a) = (((a) << (s)) | ((a) >> (32 - (s)))); \
	(a) += (b); \
}
#define II(a, b, c, d, x, s, ac) { \
	(a) += I((b), (c), (d)) + (x) + (ac); \
	(a) = (((a) << (s)) | ((a) >> (32 - (s)))); \
	(a) += (b); \
}

// Left rotation function
#define LEFT_ROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

// Initializing the Buffer
#define A 0x67452301
#define B 0xefcdab89
#define C 0x98badcfe
#define D 0x10325476

const static uint8_t K[64]={
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
	5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
	0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9};


const static uint8_t S[64] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

const static uint32_t T[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

#define MD5_UPDATE(X) { \
	uint8_t j; \
	uint32_t temp1, temp2, a = AA, b = BB, c = CC, d = DD; \
	for(uint8_t i = 0; i < 64; i++) { \
		switch(i/16) { \
			case 0: \
				temp1 = F(b, c, d); \
				j = i; \
				break; \
			case 1: \
				temp1 = G(b, c, d); \
				j = K[i]; \
				break; \
			case 2: \
				temp1 = H(b, c, d); \
				j = K[i]; \
				break; \
			case 3: \
				temp1 = I(b, c, d); \
				j = K[i]; \
				break; \
			default: \
				printf("\nError\n"); \
		} \
		temp2 = d; d = c; c = b; \
		b = b + LEFT_ROTATE(a + temp1 + X[j] + T[i], S[i]); \
		a = temp2; \
		/*printf("\nRound %d : %08x|%08x|%08x|%08x\n",i,a,b,c,d);*/ \
	} \
	AA += a; BB += b; CC += c; DD += d; \
}

uint32_t AA, BB, CC, DD;

uint64_t m_len;

// MD5_PADDING
void md5_padding(unsigned char *msg, size_t last_block_size, uint8_t pad_len) {
	size_t len = last_block_size + pad_len;
	unsigned char input[len];
	for(uint8_t i = 0; i < len; i++) {
		if (i < last_block_size)
			input[i] = msg[i];
		else if(i == last_block_size && pad_len > 0)
			input[i] = 0x80;
		else
			input[i] = 0x00;
	}
	uint32_t X[16];
	size_t k = len;
	uint8_t j = 0;
	while(k/64) {
		for(uint8_t i = 0; i < 16; i++) {
			X[i] = ((uint32_t)input[j]) | ((uint32_t)input[j + 1] << 8) | ((uint32_t)input[j + 2] << 16) | ((uint32_t)input[j + 3] << 24);
			j += 4;
		}

		for(uint8_t i = 0; i < 16; i++)
			MD5_UPDATE(X);
		k = k % 64;
	}
	for(uint8_t i = 0; i < 14; i++) {
		X[i] = ((uint32_t)input[j]) | ((uint32_t)input[j + 1] << 8) | ((uint32_t)input[j + 2] << 16) | ((uint32_t)input[j + 3] << 24);
		j += 4;
	}
	X[15] = (m_len * 8) >> 32;
	X[14] = (m_len * 8) & (uint32_t)0xffffffff;

	//for(uint8_t i = 0; i < 16; i++)
	//	printf("%08x ", X[i]);
	MD5_UPDATE(X);
}

void md5_main(unsigned char *input) {
	m_len = strlen(input);
	uint8_t no_block = m_len/64;
	uint8_t count = 0, j = 0;
	AA = A; BB = B; CC = C; DD = D;

	while(count < no_block) {
		uint32_t X[16];
		for(uint8_t i = 0; i < 16; i++) {
			X[i] = ((uint32_t)input[j]) | ((uint32_t)input[j + 1] << 8) | ((uint32_t)input[j + 2] << 16) | ((uint32_t)input[j + 3] << 24);
			j += 4;
		}
	//	for(uint8_t i = 0; i < 16; i++)
	//		printf("%08x ", X[i]);
		MD5_UPDATE(X);
		count++;
	}

	size_t last_block_size = m_len % 64;
	uint8_t pad_len = last_block_size < 56 ? 56 - last_block_size : (56 + 64) - last_block_size;
	md5_padding(&input[no_block * 64], last_block_size, pad_len);

	AA = ((AA & 0x000000FF) << 24) | ((AA & 0x0000FF00) << 8) | ((AA & 0x00FF0000) >> 8) | ((AA & 0xFF000000) >> 24);
	BB = ((BB & 0x000000FF) << 24) | ((BB & 0x0000FF00) << 8) | ((BB & 0x00FF0000) >> 8) | ((BB & 0xFF000000) >> 24);
	CC = ((CC & 0x000000FF) << 24) | ((CC & 0x0000FF00) << 8) | ((CC & 0x00FF0000) >> 8) | ((CC & 0xFF000000) >> 24);
	DD = ((DD & 0x000000FF) << 24) | ((DD & 0x0000FF00) << 8) | ((DD & 0x00FF0000) >> 8) | ((DD & 0xFF000000) >> 24);

}

int main() {
	char *input = "abc";
	md5_main(input);
	printf("Message Digest : %08x|%08x|%08x|%08x\n",AA,BB,CC,DD);
	return 0;
}
