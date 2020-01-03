#ifndef AESSIGNATURE_H
#define AESSIGNATURE_H

#include <stdlib.h>
#include <inttypes.h>


// AES
typedef struct aes_public_key_st {
    uint8_t q[144]; // 1152 bits
    uint8_t Q[25344]; // 1152 x 1408 bits => 144 x 176 bytes
} AesSignaturePublicKey;

typedef struct aes_private_key_st {
    uint8_t key[16]; // 128 bits
    uint8_t permutation[160]; // 1 .. 160, can use uint8_t
} AesSignaturePrivateKey;

typedef struct aes_signature_st {
    uint8_t nonce[16]; // we are working with 128 bit nonce
    uint8_t w[160];
} AesSignature;

int AES_signature_key_pair_generation(AesSignaturePublicKey *public_key, AesSignaturePrivateKey *private_key);

void AES_signature_sign(const uint8_t *message, size_t message_size,
                        const AesSignaturePrivateKey *private_key, AesSignature *signature);

int AES_signature_verify(const uint8_t *message, size_t message_size, const AesSignature *signature,
                         const AesSignaturePublicKey *public_key);

// verify return codes
#define SIGNATURE_OK 1
#define SIGNATURE_INVALID 2

// AES end

#endif //AESSIGNATURE_H
