# include "signature.h"

static void random_permute(int *perm, int size) {
    int i, j;

    for (i = 0; i < size; i++) {
        j = rand() % (size - i) + i;
        SWAP(perm[i], perm[j])
    }
}
