#include "key_manager.h"

#include <stdio.h>
#include <string.h>

static int hex_to_bytes(
    const char *hex,
    unsigned char *bytes,
    size_t byte_count)
{
    for (size_t i = 0; i < byte_count; i++) {
        unsigned int value;

        if (sscanf(hex + (i * 2), "%2x", &value) != 1) {
            return -1;
        }

        bytes[i] = (unsigned char)value;
    }

    return 0;
}

int key_load(
    const char *filename,
    unsigned char key[CRYPTO_KEY_SIZE])
{
    FILE *file;
    char hex_key[(CRYPTO_KEY_SIZE * 2) + 1];

    if (filename == NULL || key == NULL) {
        return -1;
    }

    file = fopen(filename, "r");

    if (file == NULL) {
        return -1;
    }

    memset(hex_key, 0, sizeof(hex_key));

    if (fread(
            hex_key,
            1,
            CRYPTO_KEY_SIZE * 2,
            file) != CRYPTO_KEY_SIZE * 2) {

        fclose(file);
        return -1;
    }

    fclose(file);

    hex_key[CRYPTO_KEY_SIZE * 2] = '\0';

    return hex_to_bytes(
        hex_key,
        key,
        CRYPTO_KEY_SIZE);
}
