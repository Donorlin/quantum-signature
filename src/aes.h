#ifndef aes_h
#define aes_h

#include <stdlib.h>
#include <stdint.h>

#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_AMD64) || defined(_M_X64))
#define SWAP(x) (_lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00)
#define GETU32(p) SWAP(*((uint32_t *)(p)))
#define PUTU32(ct, st) { *((uint32_t *)(ct)) = SWAP((st)); }
#else
#define GETU32(pt) (((uint32_t)(pt)[0] << 24) ^ ((uint32_t)(pt)[1] << 16) ^ ((uint32_t)(pt)[2] <<  8) ^ ((uint32_t)(pt)[3]))
#define PUTU32(ct, st) { (ct)[0] = (uint8_t)((st) >> 24); (ct)[1] = (uint8_t)((st) >> 16); (ct)[2] = (uint8_t)((st) >>  8); (ct)[3] = (uint8_t)(st); }

#endif

#define AES_MAXNR 14
struct aes_key_st {
    uint32_t rd_key[4 * (AES_MAXNR + 1)];
    int rounds;
};
typedef struct aes_key_st AES_KEY;

extern const uint8_t aes_s_box[256];

int AES_set_encrypt_key(const unsigned char *user_key, int bits, AES_KEY *key);

void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key, uint8_t *sbox_inputs);

void AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);

int AES_set_decrypt_key(const unsigned char *user_key, int bits, AES_KEY *key);

#endif /* aes_h */
