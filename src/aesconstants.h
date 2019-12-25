#ifndef AES_CONSTANTS_H
#define AES_CONSTANTS_H

#include <inttypes.h>

// 16x16
extern const uint8_t linear_layer_matrix_inverse[256];

// 176 x 320
extern const uint8_t aes_spn_matrix[56320];

#endif