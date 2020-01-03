#include "aessignature.h"
#include "aes.h"
#include "aesconstants.h"
#include <sodium.h>
#include <stdio.h>
#include <memory.h>
#include "galois256.h"


static void transpose(const uint8_t *matrix, const size_t nrows, const size_t ncols, uint8_t *result) {
    size_t r, c;
    for (r = 0; r < nrows; r++) {
        for (c = 0; c < ncols; c++) {
            result[c * nrows + r] = matrix[r * ncols + c];
        }
    }
}

// permute only 16 .. 160
static void random_permutation(uint8_t *perm) {
    uint8_t i, tmp;
    uint32_t j;

    for (i = 0; i < 160; i++) {
        perm[i] = i;
    }

    for (i = 16; i < 160; i++) {
        j = randombytes_uniform(160 - 16) + 16;
        tmp = perm[i];
        perm[i] = perm[j];
        perm[j] = tmp;
    }
}

static void random_bits_128(uint8_t *rnd) {
    PUTU32(rnd, randombytes_random());
    PUTU32(rnd + 4, randombytes_random());
    PUTU32(rnd + 8, randombytes_random());
    PUTU32(rnd + 12, randombytes_random());
}

// we permute pairs of bytes
// permutation is always of size 160 and vector of size 320
static void apply_pair_permutation(uint8_t *vector, const uint8_t *permutation) {
    uint8_t ind, tmp;

    for (int i = 0; i < (160 - 1); i++) {
        // get next index
        ind = permutation[i];
        while (ind < i) {
            ind = permutation[ind];
        }

        // swap elements in array
        tmp = vector[2 * i];
        vector[2 * i] = vector[2 * ind];
        vector[2 * ind] = tmp;

        tmp = vector[2 * i + 1];
        vector[2 * i + 1] = vector[2 * ind + 1];
        vector[2 * ind + 1] = tmp;
    }
}

static void apply_permutation(uint8_t *vector, const uint8_t *permutation) {
    uint8_t ind, tmp;

    for (int i = 0; i < (160 - 1); i++) {
        // get next index
        ind = permutation[i];
        while (ind < i) {
            ind = permutation[ind];
        }

        // swap elements in array
        tmp = vector[i];
        vector[i] = vector[ind];
        vector[ind] = tmp;
    }
}

static void aes_constants(AES_KEY *aes_key, uint8_t *constants) {
    int i, j, c, key;
    uint8_t key_8[16]; // for aes round key
    uint8_t mul_res[16];

    // odd = zero
    // even = byte from a round_key * linear_layer_matrix_inverse
    c = 1;
    for (key = 4, i = 0; key < 44; key += 4, i++) { // we have 10 round -> 44 x 32 bits (4 * (10 + 1))
        // put aes round key to 8bit vector
        PUTU32(key_8, aes_key->rd_key[key]);
        PUTU32(key_8 + 4, aes_key->rd_key[key + 1]);
        PUTU32(key_8 + 8, aes_key->rd_key[key + 2]);
        PUTU32(key_8 + 12, aes_key->rd_key[key + 3]);

        // clear mul_res
        memset(mul_res, 0, sizeof(mul_res));

        // round_key x linear_layer_matrix_inverse and store result in constants
        galois_256_vector_matrix_multiplication(
                key_8,
                16,
                linear_layer_matrix_inverse,
                16,
                16,
                mul_res
        );

        for (j = 0; j < 16; j++, c += 2) {
            *(constants + c) = mul_res[j];
        }
    }
}

int AES_signature_key_pair_generation(AesSignaturePublicKey *public_key, AesSignaturePrivateKey *private_key) {
    size_t i, j;
    AES_KEY aes_key;
    uint8_t constants[320] = {0};

    if (!public_key || !private_key) {
        return -1;
    }

    // generate random 128 bit key
    random_bits_128(private_key->key);

    // generate random permutation 0..159
    random_permutation(private_key->permutation);

    // aes key schedule = expand random key
    AES_set_encrypt_key(private_key->key, 128, &aes_key);

    // fill algorithm constants
    aes_constants(&aes_key, constants);

    // apply secret random permutation on constants
    apply_pair_permutation(constants, private_key->permutation);

    // apply secret random permutation on spn matrix
    // first we need a copy of it
    uint8_t aes_spn_matrix_copy[56320];
    memcpy(aes_spn_matrix_copy, aes_spn_matrix, sizeof(aes_spn_matrix));

    // permute its columns
    for (i = 0; i < 176; i++) {
        apply_pair_permutation(aes_spn_matrix_copy + i * 320, private_key->permutation);
    }

    // TODO: Finish key pair generation when you learn how to create systematic parity check matrix without identity
    // compute systematic parity check matrix
    // echelonize permuted aes_spn_matrix_copy
    galois_256_matrix_row_reduced_echelon_form(aes_spn_matrix_copy, 176, 320, 144);

    // fill Q
    transpose(aes_spn_matrix_copy, 176, 144, public_key->Q);

    // compute q
    // reconstruct transposed H
    uint8_t H_transposed[46080]; // 320 x 144
    for (i = 0; i < 320; i++) {
        for (j = 0; j < 144; j++) {
            if (i < 144) {
                if (i == j) {
                    H_transposed[i * 144 + j] = (uint8_t) 0x01;
                } else {
                    H_transposed[i * 144 + j] = (uint8_t) 0x00;
                }
            } else {
                H_transposed[i * 144 + j] = aes_spn_matrix_copy[(i - 144) * 320 + j]; // 144 x 176
            }
        }
    }
    galois_256_vector_matrix_multiplication(constants, 320, H_transposed, 320, 144, public_key->q);

    return 0;
}

void AES_signature_sign(const uint8_t *message, const size_t message_size, const AesSignaturePrivateKey *private_key,
                        AesSignature *signature) {
    size_t i;
    uint8_t nonce_message[16 + message_size];
    uint8_t p[16];
    AES_KEY enc_key;

    // 1. nonce
    // generate random nonce - we choose to generate 128 bits
    random_bits_128(signature->nonce);

    // 2. message hash
    // concat nonce and message
    memcpy(nonce_message, signature->nonce, 16 * sizeof(uint8_t));
    memcpy(nonce_message + 16, message, message_size * sizeof(uint8_t));

    // p = hash of nonce and message
    crypto_generichash(p, sizeof(p),
                       nonce_message, 16 + message_size,
                       NULL, 0
    );

    // p + key
    for (i = 0; i < 16; i++) {
        p[i] ^= private_key->key[i];
    }

    // 3. s-box inputs
    // encrypt p using key and store s-box inputs
    AES_set_encrypt_key(private_key->key, 128, &enc_key);
    AES_encrypt(p, p, &enc_key, signature->w); // in and out can overlap

    // apply secret permutation to the order of s-box inputs
    apply_permutation(signature->w, private_key->permutation);
}

int AES_signature_verify(const uint8_t *message, const size_t message_size, const AesSignature *signature,
                         const AesSignaturePublicKey *public_key) {
    size_t i, j;
    int ret;
    uint8_t nonce_message[16 + message_size];
    uint8_t h[16];
    uint8_t v[320];

    // 1. message hash
    // concat nonce and message
    memcpy(nonce_message, signature->nonce, 16 * sizeof(uint8_t));
    memcpy(nonce_message + 16, message, message_size * sizeof(uint8_t));

    // p = hash of nonce and message
    crypto_generichash(h, sizeof(h),
                       nonce_message, 16 + message_size,
                       NULL, 0
    );

    // 2. verify that hash == w[:16]
    ret = memcmp(h, signature->w, 16);

    if (ret != 0) {
        return SIGNATURE_INVALID;
    }

    // 3. construct vector v, where v_i = (w_i, Sbox(w_i))
    for (i = 0; i < 320; i += 2) {
        v[i] = signature->w[i];
        v[i + 1] = aes_s_box[signature->w[i]];
    }

    // 4. verify public q is equal to v * transposed (I|Q)
    // reconstruct transposed H as transposed (I|Q)
    uint8_t H_transposed[46080]; // 320 x 144
    for (i = 0; i < 320; i++) {
        for (j = 0; j < 144; j++) {
            if (i < 144) {
                if (i == j) {
                    H_transposed[i * 144 + j] = (uint8_t) 0x01;
                } else {
                    H_transposed[i * 144 + j] = (uint8_t) 0x00;
                }
            } else {
                H_transposed[i * 144 + j] = public_key->Q[(j - 144) * 176 + i]; // 144 x 176
            }
        }
    }

    // multiple v with H_transposed and store the result in q
    uint8_t q[144];
    galois_256_vector_matrix_multiplication(v, 320, H_transposed, 320, 144, q);

    // verify if q is equal to public q
    ret = memcmp(q, public_key->q, 144);

    if (ret != 0) {
        return SIGNATURE_INVALID;
    }

    return SIGNATURE_OK;
}