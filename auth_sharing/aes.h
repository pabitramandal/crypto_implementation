#include<stdio.h>
#include<stdint.h>
#include<string.h>
#include<stdlib.h>

#include "tables.h"


// Note: Comment out accordingly
// For AES-128
//#define Nk 4
//#define Nr 10

// For AES-192
//#define Nk 6
//#define Nr 12

// For AES-256
#define Nk 8
#define Nr 14

//uint8_t Nk, Nr;

// Declaration of Functions
void rot_word(uint8_t *word);
void sub_word(uint8_t *word);

void aes_encrypt(uint8_t *i_block, uint8_t *o_block);
void aes_decrypt(uint8_t *i_block, uint8_t *o_block);

void sub_bytes(uint8_t *state);
void inv_sub_bytes(uint8_t *state);

void shift_rows(uint8_t *state);
void inv_shift_rows(uint8_t *state);

void mix_columns(uint8_t *state);
void inv_mix_columns(uint8_t *state);

void add_roundkey(uint8_t *state, uint8_t round);

void aes_padd(uint8_t *msg, uint64_t m_len, uint8_t *p_msg, uint64_t p_mlen);

void ecb_encrypt(uint8_t *key, uint8_t *msg, uint8_t *cipher, uint8_t b_count);
void ecb_decrypt(uint8_t *key, uint8_t *cipher, uint8_t *msg, uint8_t b_count);

void cbc_encrypt(uint8_t *key, uint8_t *IV, uint8_t *msg, uint8_t *cipher, uint8_t b_count);
void cbc_decrypt(uint8_t *key, uint8_t *IV, uint8_t *cipher, uint8_t *msg, uint8_t b_count);

void ofb_encrypt(uint8_t *key, uint8_t *IV, uint8_t *msg, uint8_t *cipher, uint8_t b_count);
void ofb_decrypt(uint8_t *key, uint8_t *IV, uint8_t *cipher, uint8_t *msg, uint8_t b_count);

void ctr_encrypt(uint8_t *key, uint8_t *init_ctr, uint8_t *msg, uint8_t *cipher, uint8_t b_cout);
void ctr_decrypt(uint8_t *key, uint8_t *init_ctr, uint8_t *cipher, uint8_t *msg, uint8_t b_cout);
void increment(uint8_t *ctr);

