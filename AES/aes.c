#include "aes.h"

uint8_t expanded_key[(Nr + 1) << 4];

// AES Encryption of a 16 byte block
void aes_encrypt(uint8_t *i_block, uint8_t *o_block) {
	uint8_t i, j, round, state[16];
	for(i = 0; i < 4; i++) {
		for(j = 0; j < 4; j++)
			state[4*j + i] = i_block[4*i + j];
	}
	round = 0;
	add_roundkey(state, round);
	for(round = 1; round < Nr; round++) {
		sub_bytes(state);
		shift_rows(state);
		mix_columns(state);
		add_roundkey(state, round);
	}
	sub_bytes(state);
	shift_rows(state);
	add_roundkey(state, round);
	for(i = 0; i < 4; i++) {
		for(j = 0; j < 4; j++)
			o_block[4*j + i] = state[4*i + j];
	}
}

// AES Decryption of a 16 byte block
void aes_decrypt(uint8_t *i_block, uint8_t *o_block) {
	uint8_t i, j, round, state[16];
	for(i = 0; i < 4; i++) {
		for(j = 0; j < 4; j++)
			state[4*j + i] = i_block[4*i + j];
	}
	round = 0;
	add_roundkey(state, Nr - round);
	for(round = 1; round < Nr; round++) {
		inv_shift_rows(state);
		inv_sub_bytes(state);
		add_roundkey(state, Nr - round);
		inv_mix_columns(state);
	}
	inv_shift_rows(state);
	inv_sub_bytes(state);
	add_roundkey(state, Nr - round);
	for(i = 0; i < 4; i++) {
		for(j = 0; j < 4; j++)
			o_block[4*j + i] = state[4*i + j];
	}
}

// Key Expansion
void expand_key(uint8_t *key) {
        uint8_t i, j, temp[4];
        for(i = 0; i < Nk; i++) {
                for(uint8_t j = 0; j < 4; j++)
                        expanded_key[4*i + j] = key[4*i + j]; 
        }
        for(; i < ((Nr + 1) << 2); i++) {
                for(j = 0; j < 4; j++)
                        temp[j] = expanded_key[4*(i - 1) + j]; 
                if(0 == i % Nk) {
                        rot_word(temp);
                        sub_word(temp);
                        temp[0] = temp[0] ^ Rcon[i / Nk];
                }
                else if(Nk > 6 && 4 == i % Nk) 
                        sub_word(temp);
                for(j = 0; j < 4; j++)
                        expanded_key[4*i + j] = temp[j] ^ expanded_key[4*(i - Nk) + j]; 
        }
}

// Left Rotation
void rot_word(uint8_t *word) {
        uint8_t temp = word[0];
        word[0] = word[1];
        word[1] = word[2];
        word[2] = word[3];
        word[3] = temp;
}

// Sub word
void sub_word(uint8_t *word) {
        for(uint8_t i = 0; i < 4; i++)
                word[i] = sbox[word[i]];
}

// Add Round Key
void add_roundkey(uint8_t *state, uint8_t round) {
	for(uint8_t i = 0; i < 4; i++) {
		for(uint8_t j = 0; j < 4;  j++)
			state[i + 4*j] ^= expanded_key[16*round + i*4 + j];
	}
}

// Sub-bytes
void sub_bytes(uint8_t *state) {
	for(uint8_t i = 0; i < 16; i++)
		state[i] = sbox[state[i]];
}

// Inverse Sub-bytes
void inv_sub_bytes(uint8_t *state) {
        for(uint8_t i = 0; i < 16; i++)
                state[i] = isbox[state[i]];
}

// Shift Rows
void shift_rows(uint8_t *state) {
        uint8_t temp; \
        temp = state[4]; state[4] = state[5]; state[5] = state[6]; state[6] = state[7]; state[7] = temp;
        temp = state[8]; state[8] = state[10]; state[10] = temp;
        temp = state[9]; state[9] = state[11]; state[11] = temp;
        temp = state[12]; state[12] = state[15]; state[15] = state[14]; state[14] = state[13]; state[13] = temp;
}

// Inverse Shift Rows
void inv_shift_rows(uint8_t *state) {
        uint8_t temp;
        temp = state[7]; state[7] = state[6]; state[6] = state[5]; state[5] = state[4]; state[4] = temp;
        temp = state[10]; state[10] = state[8]; state[8] = temp;
        temp = state[11]; state[11] = state[9]; state[9] = temp;
        temp = state[13]; state[13] = state[14]; state[14] = state[15]; state[15] = state[12]; state[12] = temp;
}

// Mix Columns
void mix_columns(uint8_t *state) {
        for(uint8_t i = 0; i < 4; i++) {
                uint8_t col[4];
                for(uint8_t j = 0; j < 4; j++)
                        col[j] = state[4*j + i];
                state[0 + i] = mul2[col[0]] ^ mul3[col[1]] ^ col[2] ^ col[3];
                state[4 + i] = col[0] ^ mul2[col[1]] ^ mul3[col[2]] ^ col[3];
                state[8 + i] = col[0] ^ col[1] ^ mul2[col[2]] ^ mul3[col[3]];
                state[12 + i] = mul3[col[0]] ^ col[1] ^ col[2] ^ mul2[col[3]];
        }
}

// Inverse Mix Columns
void inv_mix_columns(uint8_t *state) {
	for(uint8_t i = 0; i < 4; i++) {
                uint8_t col[4];
                for(uint8_t j = 0; j < 4; j++)
                        col[j] = state[4*j + i];
                state[0 + i] = mul14[col[0]] ^ mul11[col[1]] ^ mul13[col[2]] ^ mul9[col[3]];
                state[4 + i] = mul9[col[0]] ^ mul14[col[1]] ^ mul11[col[2]] ^ mul13[col[3]];
                state[8 + i] = mul13[col[0]] ^ mul9[col[1]] ^ mul14[col[2]] ^ mul11[col[3]];
                state[12 + i] = mul11[col[0]] ^ mul13[col[1]] ^ mul9[col[2]] ^ mul14[col[3]];
        }
}

// AES Padding
void aes_padd(uint8_t *msg, uint64_t m_len, uint8_t *p_msg, uint64_t p_mlen) {
	uint64_t i;
	for(i = 0; i < m_len; i++)
		p_msg[i] = msg[i];
	p_msg[i++] = 0x80;
	for(; i < p_mlen; i++)
		p_msg[i] = 0x00;
}

// AES-ECB Encryption
void ecb_encrypt(uint8_t *key, uint8_t *msg, uint8_t *cipher, uint8_t b_count) {
        expand_key(key);
	for(uint8_t i = 0; i < b_count; i++)
                aes_encrypt(&msg[i << 4], &cipher[i << 4]);
}

// AES-ECB Decryption
void ecb_decrypt(uint8_t *key, uint8_t *cipher, uint8_t *msg, uint8_t b_count) {
        expand_key(key);
        for(uint8_t i = 0; i < b_count; i++)
                aes_decrypt(&cipher[i << 4], &msg[i << 4]);
}

// AES-CBC Encryption
void cbc_encrypt(uint8_t *key, uint8_t *IV, uint8_t *msg, uint8_t *cipher, uint8_t b_count) {
	expand_key(key);
	uint8_t i, j, m_block[16];
	for(j = 0; j < 16; j++)
		m_block[j] = msg[j] ^ IV[j];
	aes_encrypt(m_block, &cipher[0]);
	for(i = 1; i < b_count; i++) {
		for(j = 0; j < 16; j++)
			m_block[j] = msg[(i << 4) + j] ^ cipher[((i - 1) << 4) + j];
		aes_encrypt(m_block, &cipher[i << 4]);
	}
}

// AES-CBC Decryption
void cbc_decrypt(uint8_t *key, uint8_t *IV, uint8_t *cipher, uint8_t *msg, uint8_t b_count) {
        expand_key(key);
	uint8_t i, j;
	aes_decrypt(&cipher[0], &msg[0]);
	for(j = 0; j < 16; j++)
		msg[j] ^= IV[j];
        for(i = 1; i < b_count; i++) {
                aes_decrypt(&cipher[i << 4], &msg[i << 4]);
		for(j = 0; j < 16; j++)
			msg[(i << 4) + j] ^= cipher[((i - 1) << 4) + j];
	}
}

// AES-CFB Mode

// AES-OFB Mode
void ofb_encrypt(uint8_t *key, uint8_t *IV, uint8_t *msg, uint8_t *cipher, uint8_t b_count) {
	expand_key(key);
	uint8_t i, j;
	aes_encrypt(IV, &cipher[0]);
	for(i = 1; i < b_count; i++) {
		aes_encrypt(&cipher[(i - 1) << 4], &cipher[i << 4]);
		for(j = 0; j < 16; j++)
			cipher[((i - 1) << 4) + j] ^= msg[((i - 1) << 4) + j];
	}
	for(j = 16; j < 16; j++)
		cipher[((b_count - 1) << 4) + j] ^= msg[((b_count - 1) << 4) + j];
}

// AES-CTR Mode
void ctr_encrypt(uint8_t *key, uint8_t *init_ctr, uint8_t *msg, uint8_t *cipher, uint8_t b_count) {
        expand_key(key);
	uint8_t i, j,  ctr[16];
	for(j = 0; j < 16; j++)
		ctr[j] = init_ctr[j];
	for(i = 0; i < b_count; i++) {
		aes_encrypt(ctr, &cipher[i << 4]);
		for(j = 0; j < 16; j ++)
			cipher[(i << 4) + j] ^= msg[(i << 4) + j];
		increment(ctr);
	}
}

// Incrementing Counter
void increment(uint8_t *ctr) {
	for(uint8_t i = 0; i < 16; i++) {
		if(0xff == ctr[15 - i])
			ctr[15 - i] = 0x00;
		else {
			ctr[15 - i] += 1;
			break;
		}
	}
}


