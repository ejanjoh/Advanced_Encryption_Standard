/*******************************************************************************
 *
 *      Autor:      Jan Johansson (ejanjoh)
 *      Copyright:  
 *      Created:    2016-12-08
 *      Updated:    2017-01-19
 *
 *      Project:    Advanced Encryption Standard
 *      File name:  aes.c
 *
 *
 *      Version history mapped on changes in this file:
 *      -----------------------------------------------
 *      ver 1       Created
 *      ver 2       Updated for upload on github.com/ejanjoh
 *
 *
 *      Reference:  [1] Federal Information Processing Standards Publication 197,
 *                      Specification for the ADVANCED ENCRYPTION STANDARD (AES)
 *                      http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 *                  [2] Some notes on finite field aritmetic
 *                      https://en.wikipedia.org/wiki/Finite_field_arithmetic
 *
 ******************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include "aes.h"

#define XOR ^
#define MOD %

#define NBR_ROWS 4

static uint8_t s_box[16][16] = {
    {0x74, 0xac, 0x59, 0xb9, 0xdb, 0x55, 0xba, 0xb4, 0x76, 0xc3, 0xfe, 0x91, 0x90, 0x16, 0x5a, 0x58},
    {0x67, 0xe7, 0xb5, 0x3f, 0x18, 0x69, 0x05, 0xc9, 0xa0, 0xc2, 0x24, 0x0f, 0x6f, 0x54, 0x47, 0x34},
    {0x77, 0x30, 0x0c, 0x9d, 0xee, 0xf2, 0xc1, 0xe2, 0x2f, 0xc4, 0x6a, 0x0b, 0x3e, 0xd6, 0xcc, 0x88},
    {0x27, 0x94, 0x23, 0xc8, 0xf6, 0x35, 0x08, 0xa7, 0x73, 0x33, 0xbe, 0x9e, 0x4b, 0x5d, 0x6e, 0x02},
    {0x2d, 0xe4, 0x4f, 0x1a, 0x5e, 0xa5, 0x9c, 0x4a, 0xe8, 0x5b, 0x61, 0xd2, 0x0e, 0xb6, 0x81, 0xa2},
    {0x97, 0x84, 0x82, 0xf5, 0x86, 0x80, 0xf3, 0xa1, 0xb8, 0xb1, 0x31, 0xe3, 0xeb, 0xd1, 0x40, 0xbc},
    {0x7c, 0xd0, 0x4d, 0x9f, 0x45, 0x56, 0x8c, 0x21, 0x57, 0xd7, 0x14, 0xef, 0x13, 0x79, 0xb3, 0x4e},
    {0x2e, 0x6d, 0x46, 0x6c, 0xa4, 0xe1, 0x00, 0xa3, 0x3c, 0x26, 0xae, 0xd4, 0x1e, 0x3b, 0xe6, 0x3a},
    {0x3d, 0x53, 0x65, 0xe9, 0x0d, 0x64, 0x36, 0xb0, 0x15, 0xdd, 0xec, 0x37, 0xce, 0x01, 0x0a, 0x85},
    {0x60, 0xd9, 0xfc, 0x09, 0x1c, 0xe5, 0x7b, 0x41, 0x98, 0x12, 0xcd, 0xad, 0x7e, 0x17, 0x8d, 0x1d},
    {0x52, 0x75, 0x95, 0x50, 0x44, 0xfb, 0x10, 0xf7, 0xc0, 0x48, 0x68, 0xd5, 0xd3, 0x29, 0x03, 0xed},
    {0xb2, 0x04, 0xcf, 0x89, 0x38, 0x42, 0x63, 0xa8, 0x6b, 0xaf, 0xde, 0x32, 0x7a, 0x7f, 0xbb, 0x43},
    {0x19, 0xfa, 0xbf, 0x07, 0xf9, 0x2c, 0x7d, 0xe0, 0xf0, 0xda, 0xea, 0x8f, 0xaa, 0xf4, 0x5c, 0x96},
    {0x49, 0x5f, 0x9b, 0xc7, 0x93, 0x39, 0x83, 0x4c, 0xc5, 0xa6, 0x8a, 0x8e, 0x2a, 0x72, 0x25, 0xff},
    {0xdf, 0x20, 0x1b, 0xfd, 0xab, 0xf1, 0x78, 0x87, 0x8b, 0xd8, 0x28, 0x92, 0x66, 0xb7, 0xbd, 0x71},
    {0xcb, 0xa9, 0xca, 0xdc, 0x9a, 0x2b, 0xf8, 0x06, 0xc6, 0x70, 0x11, 0x62, 0x99, 0x1f, 0x22, 0x51}
};

static void TextToState(uint8_t *in, uint8_t state[][Nb]);
static void StateToText(uint8_t state[][Nb], uint8_t *out);
static void KeyExpansion(uint8_t *key, uint32_t *w);
static uint8_t SubstituteByte(uint8_t byte);
static void SubBytes(uint8_t state[][Nb]);
static uint32_t SubWord(uint32_t wrd);
static uint32_t RotWord(uint32_t wrd);
static uint32_t Xtime(uint32_t pol_val);
static uint32_t Rcon(uint32_t in);
static void AddRoundKey(uint8_t state[][Nb], uint32_t *w, uint32_t round);
static void ShiftRows(uint8_t state[][Nb]);
static uint8_t GF_2_8_mult(uint8_t a, uint8_t b);
static void MixColumns(uint8_t state[][Nb]);
// static void PrintBlock(uint8_t block[][Nb], uint32_t round, char *str);


void Cipher(uint8_t *plaintext, uint8_t *ciphertext, uint8_t *cipher_key)
{
    uint8_t state[NBR_ROWS][Nb];
    uint32_t w[Nb * (Nr + 1)];

    TextToState(plaintext, state);
    KeyExpansion(cipher_key, w);
    AddRoundKey(state, w, 0);

    for (uint32_t round = 1; round <= (Nr - 1); round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, w, round);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, w, Nr);
    StateToText(state, ciphertext);
    return;
}


// Copy input block to state
static void TextToState(uint8_t *in, uint8_t state[][Nb])
{
    for (uint32_t r = 0; r < NBR_ROWS; r++) {
        for (uint32_t c = 0; c < Nb; c++) {
            state[r][c] = in[r + Nb * c];
        }   // for (c = ...
    }   // for (r = ...

    return;
}


// Copy state to output block
static void StateToText(uint8_t state[][Nb], uint8_t *out)
{
    for (uint32_t r = 0; r < NBR_ROWS; r++) {
        for (uint32_t c = 0; c < Nb; c++) {
            out[r + Nb * c] = state[r][c];
        }   // for (c = ...
    }   // for (r = ...

    return;
}


// Perform a (cipher) key expansion to generate a key schedule
static void KeyExpansion(uint8_t *key, uint32_t *w)
{
    uint8_t *w8 = (uint8_t *) w;
    uint32_t temp;
    
    for (uint32_t i = 0; i < Nk; i++) {

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        w8[4 * i + 0] = key[4 * i + 3];
        w8[4 * i + 1] = key[4 * i + 2];
        w8[4 * i + 2] = key[4 * i + 1];
        w8[4 * i + 3] = key[4 * i + 0];
#endif
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        w8[4 * i + 0] = key[4 * i + 0];
        w8[4 * i + 1] = key[4 * i + 1];
        w8[4 * i + 2] = key[4 * i + 2];
        w8[4 * i + 3] = key[4 * i + 3];
#endif
    }
    
    for (uint32_t i = Nk; i < Nb * (Nr + 1); i++) {
        temp = w[i - 1];
        
        if (0 == (i MOD Nk)) {
            temp = RotWord(temp);
            temp = SubWord(temp);
            temp = temp XOR Rcon(i/Nk);
            
            // potential compiler error in OSX? Found on Linux? check it up...
            //temp = SubWord(RotWord(temp)) XOR Rcon(i/Nk);
        }
#ifdef AES_256
        else if (4 == (i MOD Nk)) {
            temp = SubWord(temp);
        }
#endif
        
        w[i] = w[i - Nk] XOR temp;
    }

    return;
}


// Substitute a byte using the S-box
static uint8_t SubstituteByte(uint8_t byte)
{
    uint32_t r, c;
    
    r = ((byte & 0xf0) >> 4);
    c= (byte & 0x0f);

    return s_box[r][c];
}


// Subsitute the bytes in the state
static void SubBytes(uint8_t state[][Nb])
{
    for (uint32_t r = 0; r < NBR_ROWS; r++) {
        for (uint32_t c = 0; c < Nb; c++) {
            state[r][c] = SubstituteByte(state[r][c]);
        }   // for (c = ...
    }   // for (r = ...

    return;
}


// Substitute four-byte input word and applies an S-box to each of the four bytes to
// produce an output word.
static uint32_t SubWord(uint32_t wrd)
{
    uint32_t w;
    uint8_t *in = (uint8_t *) &wrd;
    uint8_t *out = (uint8_t *) &w;
    
    out[0] = SubstituteByte(in[0]);
    out[1] = SubstituteByte(in[1]);
    out[2] = SubstituteByte(in[2]);
    out[3] = SubstituteByte(in[3]);
    
    return w;
}


// Takes a word [a0,a1,a2,a3] as input, performs a cyclic permutation, and returns the word [a1,a2,a3,a0]
static uint32_t RotWord(uint32_t wrd)
{
    uint32_t w;

    w = wrd << 8;
    w = w | (wrd >> 24);
    return w;
}


// Multiplying a binary polynomial by x in the field GF(2^8)
static uint32_t Xtime(uint32_t pol_val)
{
    uint32_t val;
    
    val = pol_val & 0xff;
    val = val << 1;
    
    /*
     *  If b7 = 0, the result is already in reduced form. If b7 = 1, the reduction is accomplished 
     *  by subtracting (i.e., XORing) the polynomial m(x). It follows that multiplication by x 
     *  (i.e., {00000010} or {02}) can be implemented at the byte level as a left shift and a 
     *  subsequent conditional bitwise XOR with {1b}.
     */
    
    if (0x100 & val) {
        val = val XOR 0x0000001b;
        val = val & 0xff;
    }

    return val;
}


// Rcon[i], contains the values given by [{x^(i-1)},{00},{00},{00}], with x^(i-1) being powers of x
// (x is denoted as {02}) in the field GF(2^8)
static uint32_t Rcon(uint32_t in)
{
    uint32_t ret = 0x01;

    if (0 != (in - 1)) {
        for (uint32_t i = 0; i < (in - 1); i++) {
            ret = Xtime(ret);
        }
    }

    return ret << 24;
}


// AddRoundKey:
// [s'(0,c) , s'(1,c) , s'(2,c) , s'(3,c) ] = [s(0,c) , s(1,c) , s(2,c) , s(3,c) ] xor
// [w(round*Nb+c) ] for 0 <= c < Nb,
static void AddRoundKey(uint8_t state[][Nb], uint32_t *w, uint32_t round)
{
    for (uint32_t c = 0; c < Nb; c++) {
        state[0][c] = state[0][c] XOR ((uint8_t) (0xff & (w[round*Nb+c] >> 24)));
        state[1][c] = state[1][c] XOR ((uint8_t) (0xff & (w[round*Nb+c] >> 16)));
        state[2][c] = state[2][c] XOR ((uint8_t) (0xff & (w[round*Nb+c] >> 8)));
        state[3][c] = state[3][c] XOR ((uint8_t) (0xff & (w[round*Nb+c])));
    }
    
    return;
}


// The bytes in the last three rows of the State are cyclically shifted over different
// numbers (row index) of bytes.
static void ShiftRows(uint8_t state[][Nb])
{
    uint8_t temp0, temp1, temp2;
    
    temp0 = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp0;

    temp0 = state[2][0];
    temp1 = state[2][1];
    state[2][0] = state[2][2];
    state[2][1] = state[2][3];
    state[2][2] = temp0;
    state[2][3] = temp1;

    temp0 = state[3][0];
    temp1 = state[3][1];
    temp2 = state[3][2];
    state[3][0] = state[3][3];
    state[3][1] = temp0;
    state[3][2] = temp1;
    state[3][3] = temp2;

    return;
}


// Multiply two numbers in the GF(2^8) finite field defined by the polynomial
// x^8 + x^4 + x^3 + x + 1 = 0 using the Russian Peasant Multiplication algorithm
// See ref [2]
static uint8_t GF_2_8_mult(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    
    while (b) {
        if (0x01 & b) {
            p = p XOR a;
        }
        
        if (0x80 & a) {
            a = (a << 1) XOR 0x11b;
        }
        else {
            a <<= 1;
        }
        
        b >>= 1;
    }

    return p;
}


// Let:     a(x) = {03}x3 + {01}x2 + {01}x + {02}
// Define:  s'(x) = a(x) (X) s(x)
static void MixColumns(uint8_t state[][Nb])
{
    uint8_t s0, s1, s2, s3;

    for (uint32_t c = 0; c < Nb; c++) {
        s0 = (GF_2_8_mult(0x02, state[0][c])) XOR (GF_2_8_mult(0x03, state[1][c])) XOR (state[2][c]) XOR (state[3][c]);
        s1 = (state[0][c]) XOR (GF_2_8_mult(0x02, state[1][c])) XOR (GF_2_8_mult(0x03, state[2][c])) XOR (state[3][c]);
        s2 = (state[0][c]) XOR (state[1][c]) XOR (GF_2_8_mult(0x02, state[2][c])) XOR (GF_2_8_mult(0x03, state[3][c]));
        s3 = (GF_2_8_mult(0x03, state[0][c])) XOR (state[1][c]) XOR (state[2][c]) XOR (GF_2_8_mult(0x02, state[3][c]));
        
        state[0][c] = s0;
        state[1][c] = s1;
        state[2][c] = s2;
        state[3][c] = s3;
    }
    
    return;
}


/*
// Printing intermidiate states
static void PrintBlock(uint8_t block[][Nb], uint32_t round, char *str)
{
    printf("[%2u]  %17s: ", round, str);
    
    for (uint32_t c = 0; c < NBR_ROWS; c++) {
        for (uint32_t r = 0; r < Nb; r++) {
            printf("%02x", block[r][c]);
        }   // for (c = ...
    }   // for (r = ...

    printf("\n");
    return;
}
*/



// ********************************************************************************


static uint8_t inv_s_box[16][16] = {
    {0x76, 0x8d, 0x3f, 0xae, 0xb1, 0x16, 0xf7, 0xc3, 0x36, 0x93, 0x8e, 0x2b, 0x22, 0x84, 0x4c, 0x1b},
    {0xa6, 0xfa, 0x99, 0x6c, 0x6a, 0x88, 0x0d, 0x9d, 0x14, 0xc0, 0x43, 0xe2, 0x94, 0x9f, 0x7c, 0xfd},
    {0xe1, 0x67, 0xfe, 0x32, 0x1a, 0xde, 0x79, 0x30, 0xea, 0xad, 0xdc, 0xf5, 0xc5, 0x40, 0x70, 0x28},
    {0x21, 0x5a, 0xbb, 0x39, 0x1f, 0x35, 0x86, 0x8b, 0xb4, 0xd5, 0x7f, 0x7d, 0x78, 0x80, 0x2c, 0x13},
    {0x5e, 0x97, 0xb5, 0xbf, 0xa4, 0x64, 0x72, 0x1e, 0xa9, 0xd0, 0x47, 0x3c, 0xd7, 0x62, 0x6f, 0x42},
    {0xa3, 0xff, 0xa0, 0x81, 0x1d, 0x05, 0x65, 0x68, 0x0f, 0x02, 0x0e, 0x49, 0xce, 0x3d, 0x44, 0xd1},
    {0x90, 0x4a, 0xfb, 0xb6, 0x85, 0x82, 0xec, 0x10, 0xaa, 0x15, 0x2a, 0xb8, 0x73, 0x71, 0x3e, 0x1c},
    {0xf9, 0xef, 0xdd, 0x38, 0x00, 0xa1, 0x08, 0x20, 0xe6, 0x6d, 0xbc, 0x96, 0x60, 0xc6, 0x9c, 0xbd},
    {0x55, 0x4e, 0x52, 0xd6, 0x51, 0x8f, 0x54, 0xe7, 0x2f, 0xb3, 0xda, 0xe8, 0x66, 0x9e, 0xdb, 0xcb},
    {0x0c, 0x0b, 0xeb, 0xd4, 0x31, 0xa2, 0xcf, 0x50, 0x98, 0xfc, 0xf4, 0xd2, 0x46, 0x23, 0x3b, 0x63},
    {0x18, 0x57, 0x4f, 0x77, 0x74, 0x45, 0xd9, 0x37, 0xb7, 0xf1, 0xcc, 0xe4, 0x01, 0x9b, 0x7a, 0xb9},
    {0x87, 0x59, 0xb0, 0x6e, 0x07, 0x12, 0x4d, 0xed, 0x58, 0x03, 0x06, 0xbe, 0x5f, 0xee, 0x3a, 0xc2},
    {0xa8, 0x26, 0x19, 0x09, 0x29, 0xd8, 0xf8, 0xd3, 0x33, 0x17, 0xf2, 0xf0, 0x2e, 0x9a, 0x8c, 0xb2},
    {0x61, 0x5d, 0x4b, 0xac, 0x7b, 0xab, 0x2d, 0x69, 0xe9, 0x91, 0xc9, 0x04, 0xf3, 0x89, 0xba, 0xe0},
    {0xc7, 0x75, 0x27, 0x5b, 0x41, 0x95, 0x7e, 0x11, 0x48, 0x83, 0xca, 0x5c, 0x8a, 0xaf, 0x24, 0x6b},
    {0xc8, 0xe5, 0x25, 0x56, 0xcd, 0x53, 0x34, 0xa7, 0xf6, 0xc4, 0xc1, 0xa5, 0x92, 0xe3, 0x0a, 0xdf}
};

static void InvShiftRows(uint8_t state[][Nb]);
static uint8_t InvSubstituteByte(uint8_t byte);
static void InvSubBytes(uint8_t state[][Nb]);
static void InvMixColumns(uint8_t state[][Nb]);


void InvCipher(uint8_t *ciphertext, uint8_t *plaintext, uint8_t *cipher_key)
{
    uint8_t state[NBR_ROWS][Nb];
    uint32_t w[Nb * (Nr + 1)];
    
    TextToState(ciphertext, state);
    KeyExpansion(cipher_key, w);
    AddRoundKey(state, w, Nr);
    
    for (uint32_t round = (Nr - 1); round >= 1; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, w, round);
        InvMixColumns(state);
    }
    
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, w, 0);
    
    StateToText(state, plaintext);
    return;
}


static void InvShiftRows(uint8_t state[][Nb])
{
    uint8_t temp1, temp2, temp3;
    
    temp3 = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp3;
    
    temp3 = state[2][3];
    temp2 = state[2][2];
    state[2][3] = state[2][1];
    state[2][2] = state[2][0];
    state[2][1] = temp3;
    state[2][0] = temp2;
    
    temp3 = state[3][3];
    temp2 = state[3][2];
    temp1 = state[3][1];
    state[3][3] = state[3][0];
    state[3][2] = temp3;
    state[3][1] = temp2;
    state[3][0] = temp1;
    
    return;
}


static uint8_t InvSubstituteByte(uint8_t byte)
{
    uint32_t r, c;
    
    r = ((byte & 0xf0) >> 4);
    c= (byte & 0x0f);
    
    return inv_s_box[r][c];
}


static void InvSubBytes(uint8_t state[][Nb])
{
    for (uint32_t r = 0; r < NBR_ROWS; r++) {
        for (uint32_t c = 0; c < Nb; c++) {
            state[r][c] = InvSubstituteByte(state[r][c]);
        }   // for (c = ...
    }   // for (r = ...
    
    return;
}


static void InvMixColumns(uint8_t state[][Nb])
{
    uint8_t s0, s1, s2, s3;
    
    for (uint32_t c = 0; c < Nb; c++) {
        
        s0 = (GF_2_8_mult(0x0e, state[0][c])) XOR (GF_2_8_mult(0x0b, state[1][c])) XOR
             (GF_2_8_mult(0x0d, state[2][c])) XOR (GF_2_8_mult(0x09, state[3][c]));
        s1 = (GF_2_8_mult(0x09, state[0][c])) XOR (GF_2_8_mult(0x0e, state[1][c])) XOR
             (GF_2_8_mult(0x0b, state[2][c])) XOR (GF_2_8_mult(0x0d, state[3][c]));
        s2 = (GF_2_8_mult(0x0d, state[0][c])) XOR (GF_2_8_mult(0x09, state[1][c])) XOR
             (GF_2_8_mult(0x0e, state[2][c])) XOR (GF_2_8_mult(0x0b, state[3][c]));
        s3 = (GF_2_8_mult(0x0b, state[0][c])) XOR (GF_2_8_mult(0x0d, state[1][c])) XOR
             (GF_2_8_mult(0x09, state[2][c])) XOR (GF_2_8_mult(0x0e, state[3][c]));

        state[0][c] = s0;
        state[1][c] = s1;
        state[2][c] = s2;
        state[3][c] = s3;
    }
    
    return;
}



