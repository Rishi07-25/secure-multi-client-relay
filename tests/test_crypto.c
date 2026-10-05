#define _POSIX_C_SOURCE 200809L

#include "crypto.h"

#include <stdio.h>
#include <string.h>

#define PLAINTEXT_SIZE 256
#define CIPHERTEXT_SIZE (PLAINTEXT_SIZE + CRYPTO_MAC_SIZE)

static void print_result(const char *name, int passed)
{
    printf("%s: %s\n", name, passed ? "PASS" : "FAIL");
}

int main(void)
{
    unsigned char key[CRYPTO_KEY_SIZE];
    unsigned char nonce[CRYPTO_NONCE_SIZE];

    unsigned char ciphertext[CIPHERTEXT_SIZE];
    unsigned char decrypted[PLAINTEXT_SIZE];

    size_t ciphertext_len = 0;
    size_t decrypted_len = 0;

    const char *message =
        "Secure Multi-Client Relay Server - encrypted payload test";

    size_t message_len = strlen(message);

    /*
     * Additional authenticated data.
     *
     * The plaintext remains encrypted, while the AAD is authenticated
     * but not encrypted.
     */
    const unsigned char aad[] = "relay-test-aad";
    const size_t aad_len = sizeof(aad) - 1;

    if (crypto_init() != 0) {
        printf("crypto_init: FAIL\n");
        return 1;
    }

    print_result(
        "Key generation",
        crypto_generate_key(key) == 0
    );

    print_result(
        "Nonce generation",
        crypto_generate_nonce(nonce) == 0
    );

    if (crypto_encrypt(
            key,
            nonce,
            (const unsigned char *)message,
            message_len,
            aad,
            aad_len,
            ciphertext,
            &ciphertext_len) != 0) {

        printf("Encryption: FAIL\n");
        return 1;
    }

    print_result("Encryption", 1);

    if (crypto_decrypt(
            key,
            nonce,
            ciphertext,
            ciphertext_len,
            aad,
            aad_len,
            decrypted,
            &decrypted_len) != 0) {

        printf("Decryption: FAIL\n");
        return 1;
    }

    print_result(
        "Decryption",
        decrypted_len == message_len &&
        memcmp(decrypted, message, message_len) == 0
    );

    /*
     * Tamper with the encrypted data.
     * Authenticated encryption should detect this.
     */
    ciphertext[0] ^= 0x01;

    int tamper_detected =
        crypto_decrypt(
            key,
            nonce,
            ciphertext,
            ciphertext_len,
            aad,
            aad_len,
            decrypted,
            &decrypted_len
        ) != 0;

    print_result("Tamper detection", tamper_detected);

    if (!tamper_detected) {
        printf(
            "SECURITY TEST FAILED: modified ciphertext was accepted\n"
        );
        return 1;
    }

    /*
     * Restore the ciphertext byte before testing AAD integrity.
     */
    ciphertext[0] ^= 0x01;

    /*
     * Modify the authenticated data.
     * The ciphertext itself is unchanged, but authentication
     * must fail because the AAD has been altered.
     */
    unsigned char modified_aad[sizeof(aad)];

    memcpy(modified_aad, aad, sizeof(aad));
    modified_aad[0] ^= 0x01;

    int aad_tamper_detected =
        crypto_decrypt(
            key,
            nonce,
            ciphertext,
            ciphertext_len,
            modified_aad,
            aad_len,
            decrypted,
            &decrypted_len
        ) != 0;

    print_result("AAD tamper detection", aad_tamper_detected);

    if (!aad_tamper_detected) {
        printf(
            "SECURITY TEST FAILED: modified AAD was accepted\n"
        );
        return 1;
    }

    printf("\nCrypto test PASSED\n");

    return 0;
}
