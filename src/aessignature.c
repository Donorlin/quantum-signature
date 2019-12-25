#include "aessignature.h"
#include "aes.h"
#include "aesconstants.h"
#include <sodium.h>
#include <stdio.h>
#include <memory.h>
#include "galois256.h"


static void transpose(const uint8_t *matrix, const int nrows, const int ncols, uint8_t *result) {
    int r, c;
    for (r = 0; r < nrows; r++) {
        for (c = 0; c < ncols; c++) {
            result[c * nrows + r] = matrix[r * ncols + c];
        }
    }
}

// permute only 16 .. SECRETPERMUTATIONSIZE
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
static void apply_permutation(uint8_t *vector, const uint8_t *permutation) {
    uint8_t ind, tmp;
    ind = 0;
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
    int i;
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
    apply_permutation(constants, private_key->permutation);

    // apply secret random permutation on spn matrix
    // first we need a copy of it
    uint8_t aes_spn_matrix_copy[56320];
    memcpy(aes_spn_matrix_copy, aes_spn_matrix, sizeof(aes_spn_matrix));

    // permute its columns
    for (i = 0; i < 176; i++) {
        apply_permutation(aes_spn_matrix_copy + i * 320, private_key->permutation);
    }

    // TODO: Finish key pair generation when you learn how to create systematic parity check matrix without identity
//    // compute systematic parity check matrix
//    // echelonize permuted aes_spn_matrix_copy
//    galois_256_matrix_row_reduced_echelon_form(aes_spn_matrix_copy, 176, 320, 0);
//
//    // fill Q
//    transpose(aes_spn_matrix_copy, 176, 144, public_key->Q);

    return 0;
}
