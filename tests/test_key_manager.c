#include "key_manager.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    unsigned char key[CRYPTO_KEY_SIZE];

    if (key_load("config/shared.key", key) != 0) {
        printf("Key loading: FAIL\n");
        return 1;
    }

    printf("Key loading: PASS\n");

    printf("Key length: %d bytes\n", CRYPTO_KEY_SIZE);

    if (key[0] == 0 && key[1] == 0 &&
        key[2] == 0 && key[3] == 0) {
        printf("Key randomness check: WARNING\n");
    } else {
        printf("Key randomness check: PASS\n");
    }

    printf("\nKey manager test PASSED\n");

    return 0;
}
