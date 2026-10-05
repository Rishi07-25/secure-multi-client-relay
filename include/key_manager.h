#ifndef KEY_MANAGER_H
#define KEY_MANAGER_H

#include "crypto.h"

int key_load(
    const char *filename,
    unsigned char key[CRYPTO_KEY_SIZE]
);

#endif
