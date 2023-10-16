#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<stdint.h>

// SHA-1 Functions
#define Ch(x, y, z) (( x & y) ^ (~x & z))
#define Parity(x, y, z) (x ^ y ^ z)
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

// SHA-1 Constant
static const uint32_t K[4] = {0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6};


// Initial Hash Values
#define H0 0x67452301
#define H1 0xefcdab89
#define H2 0x98badcfe
#define H3 0x10325476
#define H4 0xc3d2e1f0

// Rotate Functions
#define ROTR(x, n) ((x >> n) | (x << (32 - n)))
#define ROTL(x, n) ((x << n) | (x >> (32 - n)))

void SHA1(unsigned char *msg, uint64_t m_len, uint32_t *hash);
void compute_sha1(uint32_t *M);
void sha1_padd(unsigned char *msg, unsigned char *padded_msg, uint64_t m_len, uint8_t pad_len);
void sha1_parse(unsigned char *msg, uint32_t *M, uint64_t size);

