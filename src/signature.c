#include "signature.h"
#include "aes.h"
#include "aesconstants.h"
#include <sodium.h>

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
    int i, c, key;
    uint8_t key_8[16]; // for aes round key

    // start at 16, we want 16 bytes of 0, 16 bytes of constant, 16 bytes of zero, 16 bytes of constants ...
    c = 16;
    for (key = 0, i = 0; key < 44; key += 4, i++) { // we have 10 round -> 44 x 32 bits (4 * (10 + 1))
        // put aes round key to 8bit vector
        PUTU32(key_8, aes_key->rd_key[key]);
        PUTU32(key_8 + 4, aes_key->rd_key[key + 1]);
        PUTU32(key_8 + 8, aes_key->rd_key[key + 2]);
        PUTU32(key_8 + 12, aes_key->rd_key[key + 3]);

        // round_key x linear_layer_matrix_inverse and store result in constants
        vector_matrix_multiplication(
                key_8,
                16,
                linear_layer_matrix_inverse,
                16,
                16,
                constants + c
        );

        // move constant position
        c += 32;
    }
}

int AES_key_pair_generation(AesPublicKey *public_key, AesPrivateKey *private_key) {
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

    return 0;
}
