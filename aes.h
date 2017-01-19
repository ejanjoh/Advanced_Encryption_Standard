/*******************************************************************************
 *
 *      Autor:      Jan Johansson (ejanjoh)
 *      Copyright:  
 *      Created:    2016-12-08
 *      Updated:    2017-01-19
 *
 *      Project:    Advanced Encryption Standard
 *      File name:  aes.h
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
 *
 ******************************************************************************/

#ifndef _AES_H_
#define _AES_H_

#include <stdio.h>

#ifdef __cplusplus
    extern "C" {
#endif

/*
 *          |       1           2         3
 *          |   Key Length  Block Size  Number of
 *          |   (Nk words)  (Nb words)  Rounds
 *          |                           (Nr)
 *  ----------------------------------------------
 *  AES-128 |       4           4         10
 *  AES-192 |       6           4         12
 *  AES-256 |       8           4         14
 *
 *
 *
 *  1.  Number of 32-bit words comprising the Cipher Key. For this standard, Nk = 4, 6, or 8.
 *  2.  Number of columns (32-bit words) comprising the State. For this standard, Nb = 4.
 *  3.  Number of rounds, which is a function of Nk and Nb (which is fixed). For this
 *      standard, Nr = 10, 12, or 14.
 */


// Move to the makefile...
#define AES_128

#ifdef AES_128
    #define Nb 4
    #define Nk 4
    #define Nr 10
#endif

#ifdef AES_192
    #define Nb 4
    #define Nk 6
    #define Nr 12
#endif

#ifdef AES_256
    #define Nb 4
    #define Nk 8
    #define Nr 14
#endif


void Cipher(uint8_t *plaintext, uint8_t *ciphertext, uint8_t *cipher_key);
void InvCipher(uint8_t *ciphertext, uint8_t *plaintext, uint8_t *cipher_key);

#ifdef __cplusplus
    }
#endif

#endif /* _AES_H_ */
