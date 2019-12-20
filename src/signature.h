#ifndef SIGNATURE_H
#define SIGNATURE_H

#include <stdlib.h>
#include <inttypes.h>

// for xor-able data types
#define SWAP_TYPED(type, a, b) \
    { \
        type __swap_temp; \
        __swap_temp = (b); \
        (b) = (a); \
        (a) = __swap_temp; \
    }

// AES
typedef struct aes_public_key_st {
    uint8_t q[144]; // 1152 bits
    uint8_t Q[25344]; // 1152 x 1408 bits
} AesPublicKey;

typedef struct aes_private_key_st {
    uint8_t key[16]; // 128 bits
    uint8_t permutation[160]; // 1 .. 160, can use uint8_t
} AesPrivateKey;

typedef struct aes_signature_st {
    uint8_t nonce[16]; // we are working with 128 bit nonce
    uint8_t w[160];
} AesSignature;

int AES_key_pair_generation(AesPublicKey *public_key, AesPrivateKey *private_key);

void AES_sign_message(const char *message, const AesPrivateKey *private_key, AesSignature *signature);

int AES_verify_signature(const char *message, const AesSignature *signature, const AesPublicKey *public_key);

// AES end

#endif //SIGNATURE_H
