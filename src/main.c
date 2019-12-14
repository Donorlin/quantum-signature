#include <stdio.h>
#include "aes.h"

//void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
//int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
// 2b7e151628aed2a6abf7158809cf4f3c

int main(int argc, const char * argv[]) {
    const unsigned char key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    const unsigned char in[] = { 0x93, 0xa1, 0x70, 0x9a, 0x9c, 0x2f, 0xd4, 0xe4, 0x3a, 0x67, 0xc5, 0xf5, 0xa7, 0x64, 0x11, 0x6e };
    unsigned char enc_out[128];
    unsigned char dec_out[128];
    AES_KEY enc_key, dec_key;
    AES_SBOX_INPUTS sbox_inputs;

    AES_set_encrypt_key(key, 128, &enc_key);
    AES_encrypt(in, enc_out, &enc_key, &sbox_inputs);

    AES_set_decrypt_key(key,128,&dec_key);
    AES_decrypt(enc_out, dec_out, &dec_key);

    for(int i = 0; i < 16 * sbox_inputs.rounds; i++) {
        printf("%X\n",*(sbox_inputs.sbox_inputs + i));
    }


//    printf("original:\t");
//    int i;
//    for(i=0;*(in+i)!=0x00;i++)
//        printf("%X ",*(in+i));
//
//    printf("\nencrypted:\t");
//    for(i=0;*(enc_out+i)!=0x00;i++)
//        printf("%X ",*(enc_out+i));
//
//    printf("\ndecrypted:\t");
//    for(i=0;*(dec_out+i)!=0x00;i++)
//        printf("%X ",*(dec_out+i));
    printf("\n");

    return 0;
}
