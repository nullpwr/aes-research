#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include "aes.h"

struct Round
{
    int step;
    Rcon rcon;
    Temp_v tempv;
    State state;
    Rkey rkey;
    Box box;
    rnd next;
    rnd load;
};

// Full Round
void nextRound(Round *r)
{
    // TODO
}

void state_sub_bytes(Round *r)
{
    for (int i = 0; i < AES_KEY_SIZE; i++)
    {
        r->state.as8[i] = r->box.sbox[AES_SBOX_FIRST_BYTE][r->state.as8[i]];
    }
}

// Draft
void state_shift_rows(Round *r)
{
    memcpy(r->tempv.as8, r->state.as8, 16 * sizeof(uint8_t));

    r->state.as8[1] = r->tempv.as8[5];
    r->state.as8[5] = r->tempv.as8[9];
    r->state.as8[9] = r->tempv.as8[13];
    r->state.as8[13] = r->tempv.as8[1];

    r->state.as8[2] = r->tempv.as8[10];
    r->state.as8[10] = r->tempv.as8[2];
    r->state.as8[6] = r->tempv.as8[14];
    r->state.as8[14] = r->tempv.as8[6];

    r->state.as8[3] = r->tempv.as8[15];
    r->state.as8[7] = r->tempv.as8[3];
    r->state.as8[15] = r->tempv.as8[11];
    r->state.as8[11] = r->tempv.as8[7];

    round_reset_tempv(r);
}

// +Gemini
// Multiply by 2 in GF(2^8) - often called xtime
static uint8_t gmul2(uint8_t x)
{
    // If high bit is set, shift left and XOR with 0x1b
    return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
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
    column[0] = gmul2(a) ^ (gmul2(b) ^ b) ^ c ^ d; // 2*a + 3*b + 1*c + 1*d
    column[1] = a ^ gmul2(b) ^ (gmul2(c) ^ c) ^ d; // 1*a + 2*b + 3*c + 1*d
    column[2] = a ^ b ^ gmul2(c) ^ (gmul2(d) ^ d); // 1*a + 1*b + 2*c + 3*d
    column[3] = (gmul2(a) ^ a) ^ b ^ c ^ gmul2(d); // 3*a + 1*b + 1*c + 2*d
}

//+Gemini
//+https://en.wikipedia.org/wiki/Rijndael_MixColumns
// MixColumns transformation on the entire 4x4 state
// void mix_columns(uint8_t state[4][4]) {
void state_mix_colums(Round *r)
{
    for (int i = 0; i < 4; i++)
    {
        state_mix_column(r->state.as4x4[i]);
    }
}

void state_next_round(Round *r)
{
    state_sub_bytes(r);
    state_shift_rows(r);
    if (r->step < 10)
    {
        state_mix_colums(r);
    }
}

void rkey_next_round(Round *r)
{
    // RoundKey (temp) RotWord
    r->tempv.as32[0] = rorv32(r->rkey.as32[3], 8);

    // RoundKey SubWord (SBOX) (TODO FB?? 0x63 now)
    // see also `state_sub_bytes`
    for (int i = 0; i < 4; i++)
    {
        r->tempv.as8[i] = r->box.sbox[AES_SBOX_FIRST_BYTE][r->tempv.as8[i]];
    }

    // RoundKey12 XOR RoundConst (rcon)
    rcon_next_round(r);

    r->tempv.as32[0] = r->tempv.as32[0] ^ r->rcon.as32;

    // RoundKey32 (temp) XOR RoundKey32[idx - 4]
    r->rkey.as32[0] ^= r->tempv.as32[0];

    for (int i = 1; i < 4; i++)
    {
        r->rkey.as32[i] ^= r->rkey.as32[i - 1];
    }
    round_reset_tempv(r);
    return;
}

void rcon_next_round(Round *r)
{
    if (r->rcon.as8[0] == 0)
    {
        r->rcon.as8[0] = 0x1;
        return;
    }
    r->tempv.as32[1] = r->rcon.as8[0] << 1;
    if (r->rcon.as8[0] & 0x80)
    {
        r->tempv.as32[1] ^= 0x11B;
    }
    r->rcon.as32 = r->tempv.as32[1];
}

void round_init(Round *r)
{
    r->step = 0;
    r->rcon.as32 = 0;
    r->tempv.as64[0] = 0;
    r->tempv.as64[1] = 0;
    r->state.as64[0] = 0;
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

// Source from https://en.wikipedia.org/wiki/Rijndael_S-box
// Not tested (make both boxes)
void aes_sbox_init(Round *r)
{
    for (int i = 0; i < 256; i++)
    {
        r->tempv.as8[0] = i; // uses as block idx+fb

        uint8_t p = 1, q = 1;
        do
        {
            p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0x00);
            q ^= q << 1;
            q ^= q << 2;
            q ^= q << 4;
            q ^= q & 0x80 ? 0x09 : 0x00;
            uint8_t t = rorv8(q);
            r->tempv.as8[1] = t ^ r->tempv.as8[0];
            r->box.sbox[r->tempv.as8[0]][p] = r->tempv.as8[1];
            r->box.ibox[r->tempv.as8[0]][r->tempv.as8[1]] = p;
            // [p] = t ^ fb;
        } while (p != 1);
        r->box.sbox[r->tempv.as8[0]][0] = r->tempv.as8[0];
        r->box.ibox[r->tempv.as8[0]][r->tempv.as8[0]] = 0;
        round_reset_tempv(r);
    }
    round_reset_tempv(r);
}

void round_reset_tempv(Round *r)
{
    for (int i = 0; i < 2; i++)
    {
        r->tempv.as64[i] = 0;
    }
}

// TODO from file (other sources)
void loadRound(Round *r)
{
    uint8_t initKey[16] = {0x2b, 0x7e, 0x15, 0x16,
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

// Arm64
uint32_t rorv32(uint32_t x, uint8_t shift)
{
    int res;
    asm("rorv %w[result], %w[input_x], %w[input_shift]"
        : [result] "=r"(res)
        : [input_x] "r"(x), [input_shift] "r"(shift));
    return res;
}

// Arm64 is equal to
//uint8_t t = q ^ ROL8(q, 1) ^ ROL8(q, 2) ^ ROL8(q, 3) ^ ROL8(q, 4);
uint8_t rorv8(uint8_t x)
{
    uint8_t res = 0;
    uint8_t temp = 0;
    uint8_t t2 = 0;
    uint8_t acc = 0;
    asm("lsl %w[temp], %w[x], #1\n"
        "orr %w[acc], %w[temp], %w[x], lsr#7\n" //acc
        "lsl %w[temp], %w[x], #2\n"
        "orr %w[t2], %w[temp], %w[x], lsr#6\n" //t2
        "eor %w[temp], %w[acc], %w[t2]\n" //temp free t2 acc
        "lsl %w[t2], %w[x], #3\n"
        "orr %w[acc], %w[t2], %w[x], lsr#5\n" //temp acc free t2
        "eor %w[t2], %w[acc], %w[temp]\n" //t2 free acc temp
        "lsl %w[acc], %w[x], #4\n"
        "orr %w[temp], %w[acc], %w[x], lsr#4\n"
        "eor %w[acc], %w[temp], %w[t2]\n"
        "eor %w[res], %w[acc], %w[x]\n"
        : [res] "=r"(res)
        : [x] "r"(x),
        [temp] "r"(temp),
        [acc] "r"(acc),
        [t2] "r"(t2));
    return res;
}

void printRound(uint8_t arr[], size_t size, int emptyline)
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
        printf("%02x ", arr[i]);
    }
    printf("\n");
}

// free
void round_free(Round *r)
{
    free(r);
}

int main(void)
{
    Round round;
    round_init(&round);
    round.load(&round);
    aes_sbox_init(&round);

    // TEST START
    printf("\n-----------------PLAIN TEXT-----------------\n");
    printRound(round.state.as8, 16, 0);
    printf("\n-----------------AES----KEY-----------------\n");
    printRound(round.rkey.as8, 16, 0);

    round_xor(&round);
    do
    {
        round.step++;
        rkey_next_round(&round);
        state_next_round(&round);
        round_xor(&round);
    } while (round.step < 10); // Pseudo break. See nextRound()
    printf("\n------------------ENCODED-------------------\n");
    printRound(round.state.as8, 16, 0);
    // TEST END
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
