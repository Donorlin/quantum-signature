#ifndef aes_h
#define aes_h

# include <stdlib.h>

# define GETU32(pt) (((uint32_t)(pt)[0] << 24) ^ ((uint32_t)(pt)[1] << 16) ^ ((uint32_t)(pt)[2] <<  8) ^ ((uint32_t)(pt)[3]))
# define PUTU32(ct, st) { (ct)[0] = (uint8_t)((st) >> 24); (ct)[1] = (uint8_t)((st) >> 16); (ct)[2] = (uint8_t)((st) >>  8); (ct)[3] = (uint8_t)(st); }


# define AES_MAXNR 14
struct aes_key_st {
    uint32_t rd_key[4 * (AES_MAXNR + 1)];
    int rounds;
};
typedef struct aes_key_st AES_KEY;

struct aes_sbox_inputs_st {
    uint8_t sbox_inputs[16 * AES_MAXNR];
    int rounds;
};
typedef struct aes_sbox_inputs_st AES_SBOX_INPUTS;

int AES_set_encrypt_key(const unsigned char *user_key, const int bits, AES_KEY *key);

void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key, AES_SBOX_INPUTS *sbox_inputs);

void AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);

int AES_set_decrypt_key(const unsigned char *user_key, const int bits, AES_KEY *key);

#endif /* aes_h */
