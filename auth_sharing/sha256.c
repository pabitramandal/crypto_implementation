#include "sha256.h"

static uint32_t H[8];

void SHA256(unsigned char *msg, uint64_t m_len, uint32_t *hash) {
	uint8_t i;
	uint8_t last_block_size = m_len % 64;
	uint8_t pad_len = last_block_size < 56 ? 56 - last_block_size : (56 + 64) - last_block_size;
	uint64_t padded_mlen = m_len + pad_len + 8;
	uint8_t no_block = (padded_mlen >> 6);
	uint8_t padded_msg[padded_mlen];
	sha256_padd(msg, padded_msg, m_len, pad_len);
	uint64_t size = no_block << 4;
	uint32_t M[size];
	sha256_parse(padded_msg, M, size);
	H[0] = H0; H[1] = H1; H[2] = H2; H[3] = H3; H[4] = H4; H[5] = H5; H[6] = H6; H[7] = H7;
	for(i = 0; i < no_block; i++)
		compute_sha256(&M[i << 4]);
	for(i = 0; i < 8; i++)
		hash[i] = H[i];
}

// SHA-256 Padding
void sha256_padd(unsigned char *msg, unsigned char *padded_msg, uint64_t m_len, uint8_t pad_len) {
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

// SHA-256 Parsing
void sha256_parse(unsigned char *msg, uint32_t *M, uint64_t size) {
        for(uint64_t i = 0; i < size; i++) {
                M[i] = ((uint32_t)msg[i << 2] << 24) | ((uint32_t)msg[(i << 2) + 1] << 16) | ((uint32_t)msg[(i << 2) + 2] << 8) | ((uint32_t)msg[(i << 2) + 3]);
        }
}

// SHA-256 Hash Computation
void compute_sha256(uint32_t *M) {
	uint8_t t = 0;
	uint32_t W[64];
	for(t = 0; t < 16; t++)
		W[t] = M[t];
	for(; t < 64; t++)
		W[t] = SIG1(W[t - 2]) + W[t - 7] + SIG0(W[t - 15]) + W[t - 16];
	uint32_t a, b, c, d, e, f, g, h;
	a = H[0]; b = H[1]; c = H[2]; d = H[3]; e = H[4]; f = H[5]; g = H[6]; h = H[7];
	uint64_t T1, T2;
	for(t = 0; t < 64; t++) {
		T1 = h + SUM1(e) + CH(e, f, g) + K[t] + W[t];
		T2 = SUM0(a) + MAJ(a, b, c);
		h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;
	}
	H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

