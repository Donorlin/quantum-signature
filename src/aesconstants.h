#ifndef AES_CONSTANTS_H
#define AES_CONSTANTS_H

#include <inttypes.h>

// 16x16
extern const uint8_t linear_layer_matrix_inverse_transpose[256];

// 16x16
extern const uint8_t linear_layer_matrix_inverse[256];

// 16x16
extern const uint8_t galois_256_anti_logs[256];

// 16x16
extern const uint8_t galois_256_logs[256];


#endif