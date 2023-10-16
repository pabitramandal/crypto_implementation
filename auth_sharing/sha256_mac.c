#include "sha256_mac.h"

void sha256_hmac(unsigned char *K, uint64_t k_len, unsigned char *text, uint64_t t_len, uint32_t *HMAC) {
	uint8_t i, K0[B];
	if (k_len == B) {
		for(i = 0; i < B; i++)
			K0[i] = K[i];
	}
	else if (k_len > B) {
		SHA256(K, k_len, HMAC);
		// Copy Hash Value into K0
		for (i = 0; i < 8; i++) {
			K0[i << 2] = (HMAC[i] >> 24) & 0xff;
			K0[(i << 2) + 1] = (HMAC[i] >> 16) & 0xff;
			K0[(i << 2) + 2] = (HMAC[i] >> 8) & 0xff;
			K0[(i << 2) + 3] = HMAC[i] & 0xff;
		}
		// Append 0 into the remaining
		for (i = L; i < B; i++)
			K0[i] = 0x00;
	}
	else {
		for(i = 0; i < k_len; i++)
			K0[i] = K[i];
		for(i = k_len; i < B; i++)
			K0[i] = 0x00;
	}
	// K0 ^ ipad
	uint8_t K1[B];
	for(i = 0; i < B; i++)
		K1[i] = K0[i] ^ ipad;

	// (K0 ^ ipad) | text
	uint64_t t1_len = t_len + B;
	unsigned char text1[t1_len];
	for(i = 0; i < B; i++)
		text1[i] = K1[i];
	for(i = 0; i < t_len; i++)
		text1[B + i] = text[i];

	// SHA256((K0 ^ ipad) | text)
	SHA256(text1, t1_len, HMAC);

	// K0 ^ opad
	uint8_t K2[B];
	for(i = 0; i < B; i++)
		K2[i] = K0[i] ^ opad;
	
	//  (K0  ^ opad) | SHA256((K0 ^ipad) | text)
	uint64_t t2_len = B + L;
	uint8_t text2[t2_len];
	for(i = 0; i < B; i++)
		text2[i] = K2[i];
	for(i = 0; i < 8; i++) {
		text2[B + (i << 2)] = (HMAC[i] >> 24) & 0xff;
		text2[B + (i << 2) + 1] = (HMAC[i] >> 16) & 0xff;
		text2[B + (i << 2) + 2] = (HMAC[i] >> 8) & 0xff;
		text2[B + (i << 2) + 3] = HMAC[i] & 0xff;
	}

	// SHA256((K0  ^ opad) | SHA256((K0 ^ipad) | text))
	SHA256(text2, t2_len, HMAC);
}



