#include "signature.h"
#include "aes.h"
#include "aesconstants.h"
#include <sodium.h>
#include <memory.h>

// permute only 16 .. SECRETPERMUTATIONSIZE
static void random_permutation(uint8_t *perm) {
    uint8_t i;
    uint32_t j;

    for (i = 0; i < 160; i++) {
        perm[i] = i;
    }

    for (i = 16; i < 160; i++) {
        j = randombytes_uniform(160 - 16) + 16;
        SWAP_TYPED(uint8_t, perm[i], perm[j])
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
    uint8_t ind = 0;

    for (int i = 0; i < (160 - 1); i++) {
        // get next index
        ind = permutation[i];
        while (ind < i) {
            ind = permutation[ind];
        }

        // swap elements in array
        SWAP_TYPED(uint8_t, vector[2 * i], vector[2 * ind]);
        SWAP_TYPED(uint8_t, vector[2 * i + 1], vector[2 * ind + 1]);
    }
}

// section 2.4 Finite Field Multiplication Using Tables
// http://techheap.packetizer.com/cryptography/encryption/spec.v36.pdf
static uint8_t mul_look_up(uint8_t a, uint8_t b) {
    uint16_t t = 0;

    if (a == 0 || b == 0) {
        return 0;
    }
    t = galois_256_logs[a] + galois_256_logs[b];
    if (t > 0xff) {
        t = t - 0xff;
    }

    return galois_256_anti_logs[t];
}

static void
vector_matrix_multiplication(const uint8_t *vector, const int vector_size, const uint8_t *matrix,
                             const int matrix_nrows, const int matrix_ncols, uint8_t *result) {
    int i, j;
    // look up multiplication
    for (i = 0; i < vector_size; i++) {
        for (j = 0; j < matrix_nrows; j++) {
            result[i] ^= mul_look_up(vector[j], matrix[j * matrix_ncols + i]);
        }
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
        vector_matrix_multiplication(
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

int AES_key_pair_generation(AesPublicKey *public_key, AesPrivateKey *private_key) {
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

    return 0;
}
