#include "crypto.h"

#include <sodium.h>

int crypto_init(void)
{
    return sodium_init() < 0 ? -1 : 0;
}

int crypto_generate_key(
    unsigned char *key
)
{
    if (key == NULL) {
        return -1;
    }

    crypto_aead_xchacha20poly1305_ietf_keygen(
        key
    );

    return 0;
}

int crypto_generate_nonce(
    unsigned char *nonce
)
{
    if (nonce == NULL) {
        return -1;
    }

    randombytes_buf(
        nonce,
        CRYPTO_NONCE_SIZE
    );

    return 0;
}

int crypto_encrypt(
    const unsigned char *key,
    const unsigned char *nonce,
    const unsigned char *plaintext,
    size_t plaintext_len,
    const unsigned char *aad,
    size_t aad_len,
    unsigned char *ciphertext,
    size_t *ciphertext_len
)
{
    unsigned long long result_length = 0;

    if (key == NULL ||
        nonce == NULL ||
        plaintext == NULL ||
        ciphertext == NULL ||
        ciphertext_len == NULL) {

        return -1;
    }

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext,
            &result_length,
            plaintext,
            plaintext_len,
            aad,
            aad_len,
            NULL,
            nonce,
            key) != 0) {

        return -1;
    }

    *ciphertext_len =
        (size_t)result_length;

    return 0;
}

int crypto_decrypt(
    const unsigned char *key,
    const unsigned char *nonce,
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const unsigned char *aad,
    size_t aad_len,
    unsigned char *plaintext,
    size_t *plaintext_len
)
{
    unsigned long long result_length = 0;

    if (key == NULL ||
        nonce == NULL ||
        ciphertext == NULL ||
        plaintext == NULL ||
        plaintext_len == NULL) {

        return -1;
    }

    if (ciphertext_len < CRYPTO_MAC_SIZE) {
        return -1;
    }

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext,
            &result_length,
            NULL,
            ciphertext,
            ciphertext_len,
            aad,
            aad_len,
            nonce,
            key) != 0) {

        return -1;
    }

    *plaintext_len =
        (size_t)result_length;

    return 0;
}
