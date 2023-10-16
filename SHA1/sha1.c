#include "sha1.h"

static uint32_t H[5];

void SHA1(unsigned char *msg, uint64_t m_len, uint32_t *hash) {
	uint8_t i;
	uint8_t last_block_size = m_len % 64;
	uint8_t pad_len = last_block_size < 56 ? 56 - last_block_size : (56 + 64) - last_block_size;
	uint64_t padded_mlen = m_len + pad_len + 8;
	uint8_t no_block = (padded_mlen >> 6);
	uint8_t padded_msg[padded_mlen];
	sha1_padd(msg, padded_msg, m_len, pad_len);
	uint64_t size = no_block << 4;
	uint32_t M[size];
	sha1_parse(padded_msg, M, size);
	H[0] = H0; H[1] = H1; H[2] = H2; H[3] = H3; H[4] = H4;
	for(i = 0; i < no_block; i++)
		compute_sha1(&M[i << 4]);
	for(i = 0; i < 5; i++)
                hash[i] = H[i];

}

// SHA-1 Padding
void sha1_padd(unsigned char *msg, unsigned char *padded_msg, uint64_t m_len, uint8_t pad_len) {
	uint64_t i;
	for(i = 0; i < m_len; i++)
		padded_msg[i] = msg[i];
	padded_msg[i++] = 0x80;
	for(; i < (m_len + pad_len); i++)
		padded_msg[i] = 0x00;
	uint64_t bit_len = m_len << 3;
	for (uint8_t j = 0; j < 8; j++)
		padded_msg[i++] = (uint8_t)(bit_len >> ((7 - j) << 3));

}

// SHA-1 Parsing
void sha1_parse(unsigned char *msg, uint32_t *M, uint64_t size) {
        for(uint64_t i = 0; i < size; i++) {
                M[i] = ((uint32_t)msg[i << 2] << 24) | ((uint32_t)msg[(i << 2) + 1] << 16) | ((uint32_t)msg[(i << 2) + 2] << 8) | ((uint32_t)msg[(i << 2) + 3]);
        }
}

// SHA-1 Hash Computation
void compute_sha1(uint32_t *M) {
	uint8_t t = 0;
	uint32_t W[80];
	for(t = 0; t < 16; t++)
		W[t] = M[t];
	for(; t < 80; t++)
		W[t] = ROTL((W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]), 1);
	uint32_t a, b, c, d, e;
	a = H[0]; b = H[1]; c = H[2]; d = H[3]; e = H[4];
	uint64_t T;
	for(t = 0; t < 20; t++) {
		T = ROTL(a, 5) + (uint64_t)Ch(b, c, d) + (uint64_t)e + (uint64_t)K[0] + (uint64_t)W[t];
		e = d; d = c; c = ROTL(b, 30); b = a; a = (uint32_t)(T & 0xffffffff);
	}
        for(; t < 40; t++) {
                T = ROTL(a, 5) + (uint64_t)Parity(b, c, d) + (uint64_t)e + (uint64_t)K[1] + (uint64_t)W[t];
                e = d; d = c; c = ROTL(b, 30); b = a; a = (uint32_t)(T & 0xffffffff);
        }
        for(; t < 60; t++) {
                T = ROTL(a, 5) + (uint64_t)Maj(b, c, d) + (uint64_t)e + (uint64_t)K[2] + (uint64_t)W[t];
                e = d; d = c; c = ROTL(b, 30); b = a; a = (uint32_t)(T & 0xffffffff);
        }
        for(; t < 80; t++) {
                T = ROTL(a, 5) + (uint64_t)Parity(b, c, d) + (uint64_t)e + (uint64_t)K[3] + (uint64_t)W[t];
                e = d; d = c; c = ROTL(b, 30); b = a; a = (uint32_t)(T & 0xffffffff);
        }
	H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e;
}

