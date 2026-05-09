/*
Created by nullpwr | 15 Apr 2026
If marked
//+Gemini
that mean code was written by Gemini (Google AI), or
if marked
//+http://resource
that mean code taken from that resource

Links:
https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
https://en.wikipedia.org/wiki/Rijndael_S-box
https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf
*/
#ifndef __AES_H__
#define __AES_H__

#include <stdint.h>
#include <stdlib.h>

#define AES_SBOX_SIZE 256        // bytes
#define AES_SBOX_FIRST_BYTE 0x63 // FIPS
#define AES_KEY_SIZE 16          // 128bit

// Round controller
typedef struct Round Round;
void round_init(Round *);

// Round methods
void nextRound(Round *);
void saveRound(Round *); // not used
void loadRound(Round *); // not fully impl

// Helpers
void aes_sbox_init(Round *);

// Rotate left 8-bits width value
static inline uint8_t ROL8(uint8_t, int);

// Rotate left 32-bits value
static inline uint32_t ROL32(uint32_t, int);

// Multiply by 2 in GF(2^8)
static inline uint8_t xtime(uint8_t);

// uint8_t fb (i)SBOX first byte
// int is_temp = RKEY if true, else STATE
// int is_sbox = SBOX if true, else invSBOX
void sub_bytes(Round *r, uint8_t fb, int is_rkey, int is_sbox);

// Round key const (rcon)
uint8_t get_next_rcon(uint8_t rcon);

void round_xor(Round *);
void rkey_next_round(Round *, uint8_t fb, uint8_t set_rcon_const, int is_sbox, int is_addendum);

void state_next_round(Round *);
void state_sub_bytes(Round *);
void state_shift_rows(Round *);
void state_mix_columns(Round *);
void state_mix_column(uint8_t *);
void inv_mix_columns(uint8_t state[4][4]);
uint8_t multiply(uint8_t x, uint8_t y);
void printRound(uint8_t arr[], size_t size, int step, int is_rkey, int emptyline);

// Holds current round state
typedef union
{
    uint8_t as8[AES_KEY_SIZE];
    uint32_t as32[4];
    uint64_t as64[2];
    uint8_t as4x4[4][4];
} State, Rkey;

// Emulate struct methods
typedef void (*rnd)(Round *);

// Holds SBOX + Inverse SBOX
// Why so big? Because holds all (i)SBOX variants
// So, you can easy switch between bot
// Byte at position row[0] mean FirstByte (see FIPS)
typedef struct
{
    uint8_t sbox[AES_SBOX_SIZE][AES_SBOX_SIZE];
    uint8_t ibox[AES_SBOX_SIZE][AES_SBOX_SIZE];
} Box;

#endif //__AES_H__
