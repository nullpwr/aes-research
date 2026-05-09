#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include "aes.h"

struct Round
{
    int step;
    uint32_t rcon;
    State state;
    Rkey rkey;
    Box box;
    rnd next;
    rnd load;
};

static inline uint8_t ROL8(uint8_t v, int n)
{
    return (uint8_t)((v << n) | (v >> (8 - n)));
}

static inline uint32_t ROL32(uint32_t v, int n)
{
    return (uint32_t)((v << (32 - n)) | (v >> n));
}

static inline uint8_t xtime(uint8_t x)
{
    return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
}

void sub_bytes(Round *r, uint8_t fb, int is_rkey, int is_sbox)
{
    uint8_t *arr = (is_rkey) ? r->rkey.as4x4[3] : r->state.as8;
    size_t count = (is_rkey) ? 4 : 16;

    for (int i = 0; i < count; i++)
    {
        arr[i] = *(((is_sbox) ? r->box.sbox[fb] : r->box.ibox[fb])+arr[i]);
    }
}

// Full Round
void nextRound(Round *r)
{
    // TODO
}

// Draft
void state_shift_rows(Round *r)
{
    uint8_t arr[16];
    memcpy(arr, r->state.as8, 16 * sizeof(uint8_t));

    r->state.as8[1] = arr[5];
    r->state.as8[5] = arr[9];
    r->state.as8[9] = arr[13];
    r->state.as8[13] = arr[1];

    r->state.as8[2] = arr[10];
    r->state.as8[10] = arr[2];
    r->state.as8[6] = arr[14];
    r->state.as8[14] = arr[6];

    r->state.as8[3] = arr[15];
    r->state.as8[7] = arr[3];
    r->state.as8[15] = arr[11];
    r->state.as8[11] = arr[7];
}

//+Gemini
// Mixes a single column of 4 bytes
void state_mix_column(uint8_t *column)
{
    uint8_t a = column[0];
    uint8_t b = column[1];
    uint8_t c = column[2];
    uint8_t d = column[3];

    // Formula for each resulting byte in the column
    // The coefficients are: 02, 03, 01, 01 (rotated for each row)
    column[0] = xtime(a) ^ (xtime(b) ^ b) ^ c ^ d; // 2*a + 3*b + 1*c + 1*d
    column[1] = a ^ xtime(b) ^ (xtime(c) ^ c) ^ d; // 1*a + 2*b + 3*c + 1*d
    column[2] = a ^ b ^ xtime(c) ^ (xtime(d) ^ d); // 1*a + 1*b + 2*c + 3*d
    column[3] = (xtime(a) ^ a) ^ b ^ c ^ xtime(d); // 3*a + 1*b + 1*c + 2*d
}

//+Gemini
//+https://en.wikipedia.org/wiki/Rijndael_MixColumns
// MixColumns transformation on the entire 4x4 state
// void mix_columns(uint8_t state[4][4]) {
void state_mix_columns(Round *r)
{
    for (int i = 0; i < 4; i++)
    {
        state_mix_column(r->state.as4x4[i]);
    }
}

void state_next_round(Round *r)
{
    //state_sub_bytes(r);
    sub_bytes(r, AES_SBOX_FIRST_BYTE, 0, 1);
    state_shift_rows(r);
    if (r->step < 10)
    {
        state_mix_columns(r);
    }
}

void rkey_next_round(Round *r, uint8_t fb, uint8_t set_rcon_const, int is_sbox, int is_addendum)
{
    // RoundKey (temp) RotWord || ASM64 have ROR
    uint32_t orig = r->rkey.as32[3];
    r->rkey.as32[3] = ROL32(r->rkey.as32[3], 8);

    // RoundKey (temp) SubWord ((i)SBOX)
    sub_bytes(r, fb, 1, is_sbox);

    // rcon_next_round(r);
    r->rcon = (set_rcon_const) ? set_rcon_const : get_next_rcon(r->rcon);

    //TEST TEST
    if (is_addendum)
        r->rcon = (is_sbox) ? r->box.sbox[r->rcon][r->rcon] : r->box.ibox[r->rcon][r->rcon];

    r->rkey.as8[12] ^= r->rcon;

    // RoundKey32 (temp) XOR RoundKey32[idx - 4]
    r->rkey.as32[0] ^= r->rkey.as32[3];
    for (int i = 1; i < 3; i++)
    {
    r->rkey.as32[i] ^= r->rkey.as32[i-1];
    }
    r->rkey.as32[3] = orig ^ r->rkey.as32[2];
}

uint8_t get_next_rcon(uint8_t rcon)
{
    uint8_t temp;
    if (rcon == 0) return 1;


    temp = rcon << 1;

    if (rcon&0x80) temp ^= 0x1B;

    return temp;
}

void round_init(Round *r)
{
    r->step = 0;
    r->rcon = 0;
    0[r->state.as64] = 0;
    r->state.as64[1] = 0;
    r->rkey.as64[0] = 0;
    r->rkey.as64[1] = 0;
    r->next = nextRound;
    r->load = loadRound;
}

void round_xor(Round *r)
{
    for (int i = 0; i < 2; i++)
    {
        r->state.as64[i] ^= r->rkey.as64[i];
    }
}

// Source https://en.wikipedia.org/wiki/Rijndael_S-box
void aes_sbox_init(Round *r)
{
    for (int i = 0; i < 256; i++)
    {
        i = i; // uses as block idx+fb

        uint8_t p = 1, q = 1;
        do
        {
            p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0x00);
            q ^= q << 1;
            q ^= q << 2;
            q ^= q << 4;
            q ^= q & 0x80 ? 0x09 : 0x00;
            uint8_t t = q ^ ROL8(q, 1) ^ ROL8(q, 2) ^ ROL8(q, 3) ^ ROL8(q, 4);
            t ^= i;
            r->box.sbox[i][p] = t;
            r->box.ibox[i][t] = p;
            // [p] = t ^ fb;
        } while (p != 1);
        r->box.sbox[i][0] = i;
        r->box.ibox[i][i] = 0;
    }
}

// TODO from file (other sources)
void loadRound(Round *r)
{
    uint8_t initKey[16] =   {0x2b, 0x7e, 0x15, 0x16,
                            0x28, 0xae, 0xd2, 0xa6,
                            0xab, 0xf7, 0x15, 0x88,
                            0x09, 0xcf, 0x4f, 0x3c};
    uint8_t plainText[16] = {0x32, 0x43, 0xf6, 0xa8,
                             0x88, 0x5a, 0x30, 0x8d,
                             0x31, 0x31, 0x98, 0xa2,
                             0xe0, 0x37, 0x07, 0x34};

    memcpy(r->rkey.as8, initKey, 16 * sizeof(uint8_t));
    memcpy(r->state.as8, plainText, 16 * sizeof(uint8_t));
}

void printRound(uint8_t arr[], size_t size, int step, int is_rkey, int emptyline)
{
    if (emptyline)
        printf("\n\n");
    for (int i = 0; i < size; i++)
    {
        if (size > 255)
        {
            if ((i & 0xF) == 0)
            {
                printf("\n");
            }
            if ((i & 0xFF) == 0)
            {
                printf("\n");
            }
        }
        printf("%02x|%02x ", i, arr[i]);
    }
    if (step)
        printf(" %d %d\n", is_rkey, step);
}

// Multiply by any value using xtime and XOR
uint8_t multiply(uint8_t x, uint8_t y) {
    uint8_t res = 0;
    for (int i = 0; i < 4; i++) {
        if ((y >> i) & 1) {
            uint8_t temp = x;
            for (int j = 0; j < i; j++) temp = xtime(temp);
            res ^= temp;
        }
    }
    // Specific powers for Inverse MixColumns: 9, 11, 13, 14
    // Simplified per [Stack Exchange]:
    // x*9  = xtime(xtime(xtime(x))) ^ x
    // x*11 = xtime(xtime(xtime(x)) ^ xtime(x)) ^ x
    // x*13 = xtime(xtime(xtime(x) ^ x)) ^ x
    // x*14 = xtime(xtime(xtime(x) ^ x) ^ x)
    return res;
}

void inv_mix_columns(uint8_t state[4][4]) {
    uint8_t tmp[4];
    for (int i = 0; i < 4; i++) {
        tmp[0] = multiply(state[0][i], 0x0e) ^ multiply(state[1][i], 0x0b) ^
                 multiply(state[2][i], 0x0d) ^ multiply(state[3][i], 0x09);
        tmp[1] = multiply(state[0][i], 0x09) ^ multiply(state[1][i], 0x0e) ^
                 multiply(state[2][i], 0x0b) ^ multiply(state[3][i], 0x0d);
        tmp[2] = multiply(state[0][i], 0x0d) ^ multiply(state[1][i], 0x09) ^
                 multiply(state[2][i], 0x0e) ^ multiply(state[3][i], 0x0b);
        tmp[3] = multiply(state[0][i], 0x0b) ^ multiply(state[1][i], 0x0d) ^
                 multiply(state[2][i], 0x09) ^ multiply(state[3][i], 0x0e);

        for (int j = 0; j < 4; j++) state[j][i] = tmp[j];
    }
}

int main(void)
{
    Round round;
    round_init(&round);
    round.load(&round);
    aes_sbox_init(&round);

    round_xor(&round);
    do
    {
        round.step++;
        rkey_next_round(&round, AES_SBOX_FIRST_BYTE, 0, 1, 0);
        state_next_round(&round);
        round_xor(&round);
    } while (round.step < 10); // Pseudo break. See nextRound()

    for (int i = 0; i < 16; i++)
    {
        uint8_t fb = round.state.as8[i];
        uint8_t temp = fb;
        uint8_t xxor = fb;
        uint8_t limit = 64;
        do
        {
            printf("%02x|%02x ", temp, xxor);
            temp = get_next_rcon(temp);
            xxor ^= temp;
            limit--;
        } while (limit > 0);
        printf("\n\n");
    }

    // for (int i = 0; i < 16; i++)
    // {
    //     uint8_t temp = round.state.as8[i];
    //     for (int i = 0; i < 256; i++)
    //     {
    //         uint8_t *arr = round.box.ibox[i];
    //         uint8_t once[256] = {0};
    //         uint8_t cur = temp;
    //         once[temp] = 1;
    //         printf("%02x=%02x ", temp, arr[0]);
    //         int limit = 64;
    //         do
    //         {
    //             cur ^= arr[cur];
    //             printf("%02x ", cur);
    //             if (once[cur])
    //             {
    //                 printf(" ring");
    //                 limit = 0;
    //             }
    //             else
    //             {
    //                 once[cur] = 1;
    //             }
    //             limit--;
    //             if (limit == 0) printf(" limit");
    //         } while (limit > 0);
    //         printf("\n");
    //     }
    //     printf("\n\n");
    // }

    //memcpy(round.rkey.as8, round.state.as8, AES_KEY_SIZE * sizeof(uint8_t));

    // round.rkey.as8[0] = 0xd0; //d014f9a8b490130dd48177597cc75be7 random
    // round.rkey.as8[1] = 0x14;
    // round.rkey.as8[2] = 0xf9;
    // round.rkey.as8[3] = 0xa8;
    // round.rkey.as8[4] = 0xb4;
    // round.rkey.as8[5] = 0x90;
    // round.rkey.as8[6] = 0x13;
    // round.rkey.as8[7] = 0x0d;
    // round.rkey.as8[8] = 0xd4;
    // round.rkey.as8[9] = 0x81;
    // round.rkey.as8[10] = 0x77;
    // round.rkey.as8[11] = 0x59;
    // round.rkey.as8[12] = 0x7c;
    // round.rkey.as8[13] = 0xc7;
    // round.rkey.as8[14] = 0x5b;
    // round.rkey.as8[15] = 0xe7;
    //printRound(round.rkey.as8, 16, 0, 1, 0);
    //printRound(round.state.as8, 16, 0, 0, 0);
    return 0;
}

//+Gemini
/*
#include <stdint.h>

// Multiply by 2 in GF(2^8) - often called 'xtime'
uint8_t xtime(uint8_t x) {
    return (x << 1) ^ (((x >> 7) & 1) ? 0x1b : 0);
}

// Multiply by any value using xtime and XOR
uint8_t multiply(uint8_t x, uint8_t y) {
    uint8_t res = 0;
    for (int i = 0; i < 4; i++) {
        if ((y >> i) & 1) {
            uint8_t temp = x;
            for (int j = 0; j < i; j++) temp = xtime(temp);
            res ^= temp;
        }
    }
    // Specific powers for Inverse MixColumns: 9, 11, 13, 14
    // Simplified per [Stack Exchange]:
    // x*9  = xtime(xtime(xtime(x))) ^ x
    // x*11 = xtime(xtime(xtime(x)) ^ xtime(x)) ^ x
    // x*13 = xtime(xtime(xtime(x) ^ x)) ^ x
    // x*14 = xtime(xtime(xtime(x) ^ x) ^ x)
    return res;
}

void inv_mix_columns(uint8_t state[4][4]) {
    uint8_t tmp[4];
    for (int i = 0; i < 4; i++) {
        tmp[0] = multiply(state[0][i], 0x0e) ^ multiply(state[1][i], 0x0b) ^
                 multiply(state[2][i], 0x0d) ^ multiply(state[3][i], 0x09);
        tmp[1] = multiply(state[0][i], 0x09) ^ multiply(state[1][i], 0x0e) ^
                 multiply(state[2][i], 0x0b) ^ multiply(state[3][i], 0x0d);
        tmp[2] = multiply(state[0][i], 0x0d) ^ multiply(state[1][i], 0x09) ^
                 multiply(state[2][i], 0x0e) ^ multiply(state[3][i], 0x0b);
        tmp[3] = multiply(state[0][i], 0x0b) ^ multiply(state[1][i], 0x0d) ^
                 multiply(state[2][i], 0x09) ^ multiply(state[3][i], 0x0e);

        for (int j = 0; j < 4; j++) state[j][i] = tmp[j];
    }
}
*/
