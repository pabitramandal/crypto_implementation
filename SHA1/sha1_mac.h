#include<stdio.h>
#include<stdint.h>
#include<string.h>

// B : Block size (in bytes) of the input to the Approved hash function
#define B 64

// L : Block size (in bytes) of the output of the Approved hash function.
#define L 20

// HMAC constants
#define ipad 0x36
#define opad 0x5c

// Declarations of functions
void sha1_hmac(unsigned char *K, uint64_t k_len, unsigned char *text, uint64_t t_len, uint32_t *HMAC);
void SHA1(unsigned char *msg, uint64_t m_len, uint32_t *hash);


