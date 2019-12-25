
#ifndef SIGNATURE_GALOIS256_H
#define SIGNATURE_GALOIS256_H

#include <stdint.h>

// 16x16
extern const uint8_t galois_256_anti_logs[256];

// 16x16
extern const uint8_t galois_256_logs[256];

uint8_t galois_256_multiplication_look_up(uint8_t a, uint8_t b);

uint8_t galois_256_inverse_look_up(uint8_t a);

void galois_256_matrix_row_reduced_echelon_form(uint8_t *matrix, int nrows, int ncols, int start_col);

void galois_256_vector_matrix_multiplication(const uint8_t *vector, int vector_size, const uint8_t *matrix,
                                             int matrix_nrows, int matrix_ncols, uint8_t *result);

#endif //SIGNATURE_GALOIS256_H
