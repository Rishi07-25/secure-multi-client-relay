#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

#define CRYPTO_KEY_SIZE 32
#define CRYPTO_NONCE_SIZE 24
#define CRYPTO_MAC_SIZE 16

int crypto_init(void);

int crypto_generate_key(
    unsigned char *key
);

int crypto_generate_nonce(
    unsigned char *nonce
);

int crypto_encrypt(
    const unsigned char *key,
    const unsigned char *nonce,
    const unsigned char *plaintext,
    size_t plaintext_len,
    const unsigned char *aad,
    size_t aad_len,
    unsigned char *ciphertext,
    size_t *ciphertext_len
);

int crypto_decrypt(
    const unsigned char *key,
    const unsigned char *nonce,
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const unsigned char *aad,
    size_t aad_len,
    unsigned char *plaintext,
    size_t *plaintext_len
);

#endif
