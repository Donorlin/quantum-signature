#include <stdlib.h>

#ifndef SIGNATURE_H
#define SIGNATURE_H

// for xor-able data types
#define SWAP(a, b) \
    { \
        (a) ^= (b); \
        (b) ^= (a); \
        (a) ^= (b); \
    }

// ################# AES #################
# define AES_NS 16
# define AES_NR 10

struct aes_public_key_st {
    uint64_t q[((2 * AES_NS * AES_NR) - (AES_NS * (AES_NR + 1))) / 8]; // (number of sbox inputs and ouputs) * number of rounds * number of rounds
    int q_size; // ((2 * AES_NS * AES_NR) - (AES_NS * (AES_NR + 1))) / 8

    uint64_t Q[(AES_NS * AES_NR * AES_NS * (AES_NR + 1)) / 32];
    int Q_nrows; // AES_NS * AES_NR / 4
    int Q_ncols; // AES_NS * (AES_NR + 1) / 8
};
typedef struct aes_public_key_st AES_PUBLIC_KEY;

struct aes_private_key_st {
    uint8_t *user_key;
    int user_key_bits;
    int permutation[AES_NS * AES_NR];
    int permutation_size;
};
typedef struct aes_private_key_st AES_PRIVATE_KEY;

struct aes_signature_st {
    uint8_t *nonce;
    int nonce_bits;

    uint8_t w[AES_NS * AES_NR];
    int nw;
};
typedef struct aes_signature_st AES_SIGNATURE;

void AES_key_pair_generation(const uint8_t *user_key, const int bits, AES_PUBLIC_KEY *public_key,
                             AES_PRIVATE_KEY *private_key);

void AES_sign_message(const char *message, const AES_PRIVATE_KEY *private_key);

void AES_verify_signature(const char *message, const AES_SIGNATURE *signature, const AES_PUBLIC_KEY *public_key);

#endif //SIGNATURE_H
