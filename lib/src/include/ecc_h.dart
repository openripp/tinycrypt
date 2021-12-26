part of tiny_crypt;

/* ecc.h - TinyCrypt interface to common ECC functions */

/* Copyright (c) 2014, Kenneth MacKay
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 *  Copyright (C) 2017 by Intel Corporation, All Rights Reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *    - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *    - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *    - Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 * @brief -- Interface to common ECC functions.
 *
 *  Overview: This software is an implementation of common functions
 *            necessary to elliptic curve cryptography. This implementation uses
 *            curve NIST p-256.
 *
 *  Security: The curve NIST p-256 provides approximately 128 bits of security.
 *
 */


/* Word size (4 bytes considering 32-bits architectures) */
const uECC_WORD_SIZE = 4;

/* setting max number of calls to prng: */
const uECC_RNG_MAX_TRIES = 64;

/* defining data types to store word and bit counts: */
typedef wordcount_t = int8_t;
typedef bitcount_t = int16_t;
/* defining data type for comparison result: */
typedef cmpresult_t = int8_t;
/* defining data type to store ECC coordinate/point in 32bits words: */
typedef uECC_word_t = int;
/* defining data type to store an ECC coordinate/point in 64bits words: */
typedef uECC_dword_t = uint64_t;

/* defining masks useful for ecc computations: */
const HIGH_BIT_SET = 0x80000000;
const uECC_WORD_BITS = 32;
const uECC_WORD_BITS_SHIFT = 5;
const uECC_WORD_BITS_MASK = 0x01F;

/* Number of words of 32 bits to represent an element of the the curve p-256: */
const NUM_ECC_WORDS = 8;
/* Number of bytes to represent an element of the the curve p-256: */
const NUM_ECC_BYTES = (uECC_WORD_SIZE*NUM_ECC_WORDS);

/* structure that represents an elliptic curve (e.g. p256):*/
class uECC_Curve_t {
  late wordcount_t num_words;
  late wordcount_t num_bytes;
  late bitcount_t num_n_bits;
  late uECC_word_t_List p; // [NUM_ECC_WORDS];
  late uECC_word_t_List n; // [NUM_ECC_WORDS];
  late uECC_word_t_List G; // [NUM_ECC_WORDS * 2];
  late uECC_word_t_List b; // [NUM_ECC_WORDS];

  late void Function(uECC_word_t_List X1, uECC_word_t_List Y1, uECC_word_t_List Z1, uECC_Curve curve) double_jacobian;
  late void Function(uECC_word_t_List result, uECC_word_t_List x, uECC_Curve curve) x_side;
  late void Function(uECC_word_t_List result, uECC_word_t_List product) mmod_fast;
}

typedef uECC_Curve = uECC_Curve_t;

/* Bytes to words ordering: */
uECC_word_t_List BYTES_TO_WORDS_8(int a, int b, int c, int d, int e, int f, int g, int h) => [[d, c, b, a].bytes.toInt().uint32, [h, g, f, e].bytes.toInt().uint32].to_uECC_word_t_List();
int BYTES_TO_WORDS_4(int a, int b, int c, int d) => <int>[ d, c, b, a ].bytes.toInt().uint32;
int BITS_TO_WORDS(int num_bits) =>
    ((num_bits + ((uECC_WORD_SIZE * 8) - 1)) ~/ (uECC_WORD_SIZE * 8));

int BITS_TO_BYTES(int num_bits) => ((num_bits + 7) ~/ 8);

/* definition of curve NIST p-256: */
final uECC_Curve_t curve_secp256r1 = uECC_Curve_t()
  ..num_words = NUM_ECC_WORDS
  ..num_bytes = NUM_ECC_BYTES
  ..num_n_bits = 256 /* num_n_bits */
  ..p = [
    ...BYTES_TO_WORDS_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
    ...BYTES_TO_WORDS_8(0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00),
    ...BYTES_TO_WORDS_8(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
    ...BYTES_TO_WORDS_8(0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF)
  ].to_uECC_word_t_List()
  ..n = [
    ...BYTES_TO_WORDS_8(0x51, 0x25, 0x63, 0xFC, 0xC2, 0xCA, 0xB9, 0xF3),
    ...BYTES_TO_WORDS_8(0x84, 0x9E, 0x17, 0xA7, 0xAD, 0xFA, 0xE6, 0xBC),
    ...BYTES_TO_WORDS_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
    ...BYTES_TO_WORDS_8(0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF)
  ].to_uECC_word_t_List()
  ..G = [
    ...BYTES_TO_WORDS_8(0x96, 0xC2, 0x98, 0xD8, 0x45, 0x39, 0xA1, 0xF4),
    ...BYTES_TO_WORDS_8(0xA0, 0x33, 0xEB, 0x2D, 0x81, 0x7D, 0x03, 0x77),
    ...BYTES_TO_WORDS_8(0xF2, 0x40, 0xA4, 0x63, 0xE5, 0xE6, 0xBC, 0xF8),
    ...BYTES_TO_WORDS_8(0x47, 0x42, 0x2C, 0xE1, 0xF2, 0xD1, 0x17, 0x6B),

    ...BYTES_TO_WORDS_8(0xF5, 0x51, 0xBF, 0x37, 0x68, 0x40, 0xB6, 0xCB),
    ...BYTES_TO_WORDS_8(0xCE, 0x5E, 0x31, 0x6B, 0x57, 0x33, 0xCE, 0x2B),
    ...BYTES_TO_WORDS_8(0x16, 0x9E, 0x0F, 0x7C, 0x4A, 0xEB, 0xE7, 0x8E),
    ...BYTES_TO_WORDS_8(0x9B, 0x7F, 0x1A, 0xFE, 0xE2, 0x42, 0xE3, 0x4F)
  ].to_uECC_word_t_List()
  ..b = [
    ...BYTES_TO_WORDS_8(0x4B, 0x60, 0xD2, 0x27, 0x3E, 0x3C, 0xCE, 0x3B),
    ...BYTES_TO_WORDS_8(0xF6, 0xB0, 0x53, 0xCC, 0xB0, 0x06, 0x1D, 0x65),
    ...BYTES_TO_WORDS_8(0xBC, 0x86, 0x98, 0x76, 0x55, 0xBD, 0xEB, 0xB3),
    ...BYTES_TO_WORDS_8(0xE7, 0x93, 0x3A, 0xAA, 0xD8, 0x35, 0xC6, 0x5A)
  ].to_uECC_word_t_List()

  ..double_jacobian = double_jacobian_default
  ..x_side = x_side_default
  ..mmod_fast = vli_mmod_fast_secp256r1
;


typedef int uECC_RNG_Function(Uint8List dest, int size);
