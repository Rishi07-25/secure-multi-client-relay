#include "crypto.h"
#include "protocol.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    unsigned char key[
        CRYPTO_KEY_SIZE
    ];

    unsigned char frame[
        PROTOCOL_MAX_FRAME_SIZE
    ];

    unsigned char plaintext[
        PROTOCOL_MAX_PAYLOAD
    ];

    size_t frame_length = 0;
    size_t plaintext_length = 0;

    const char *message =
        "Hello secure relay";

    if (crypto_init() != 0) {
        printf(
            "Crypto initialization: FAIL\n"
        );
        return 1;
    }

    if (crypto_generate_key(key) != 0) {
        printf(
            "Key generation: FAIL\n"
        );
        return 1;
    }

    /*
     * Build encrypted message.
     */
    if (protocol_build_message_frame(
            key,
            1,
            2,
            0,
            (const unsigned char *)message,
            strlen(message),
            frame,
            sizeof(frame),
            &frame_length
        ) != 0) {

        printf(
            "Protocol encryption: FAIL\n"
        );

        return 1;
    }

    printf(
        "Protocol encryption: PASS\n"
    );

    printf(
        "Frame size: %zu bytes\n",
        frame_length
    );

    /*
     * Parse routing metadata.
     */
    protocol_frame_info info;

    if (protocol_parse_frame(
            frame,
            frame_length,
            &info
        ) != 0) {

        printf(
            "Frame parsing: FAIL\n"
        );

        return 1;
    }

    if (info.sender_id != 1 ||
        info.target_id != 2 ||
        info.type !=
            PROTOCOL_TYPE_MESSAGE) {

        printf(
            "Routing metadata: FAIL\n"
        );

        return 1;
    }

    printf(
        "Routing metadata: PASS\n"
    );

    /*
     * Decrypt.
     */
    if (protocol_decrypt_message(
            key,
            frame,
            frame_length,
            plaintext,
            sizeof(plaintext),
            &plaintext_length
        ) != 0) {

        printf(
            "Protocol decryption: FAIL\n"
        );

        return 1;
    }

    if (plaintext_length !=
            strlen(message) ||
        memcmp(
            plaintext,
            message,
            plaintext_length
        ) != 0) {

        printf(
            "Message integrity: FAIL\n"
        );

        return 1;
    }

    printf(
        "Protocol decryption: PASS\n"
    );

    printf(
        "Message integrity: PASS\n"
    );

    /*
     * Tamper ciphertext.
     */
    frame[
        PROTOCOL_HEADER_SIZE
    ] ^= 0x01;

    if (protocol_decrypt_message(
            key,
            frame,
            frame_length,
            plaintext,
            sizeof(plaintext),
            &plaintext_length
        ) == 0) {

        printf(
            "Ciphertext tamper detection: FAIL\n"
        );

        return 1;
    }

    printf(
        "Ciphertext tamper detection: PASS\n"
    );

    /*
     * Rebuild valid frame.
     */
    if (protocol_build_message_frame(
            key,
            1,
            2,
            0,
            (const unsigned char *)message,
            strlen(message),
            frame,
            sizeof(frame),
            &frame_length
        ) != 0) {

        return 1;
    }

    /*
     * Tamper target ID.
     *
     * It is authenticated as AAD, so decryption
     * must fail.
     */
    frame[9] ^= 0x01;

    if (protocol_decrypt_message(
            key,
            frame,
            frame_length,
            plaintext,
            sizeof(plaintext),
            &plaintext_length
        ) == 0) {

        printf(
            "AAD routing tamper detection: FAIL\n"
        );

        return 1;
    }

    printf(
        "AAD routing tamper detection: PASS\n"
    );

    /*
     * Invalid version.
     */
    frame[0] = 99;

    if (protocol_parse_frame(
            frame,
            frame_length,
            &info
        ) == 0) {

        printf(
            "Invalid version rejection: FAIL\n"
        );

        return 1;
    }

    printf(
        "Invalid version rejection: PASS\n"
    );

    /*
     * Client ID frame.
     */
    size_t id_length = 0;

    if (protocol_build_client_id_frame(
            42,
            frame,
            sizeof(frame),
            &id_length
        ) != 0) {

        printf(
            "Client ID frame: FAIL\n"
        );

        return 1;
    }

    if (protocol_parse_frame(
            frame,
            id_length,
            &info
        ) != 0 ||
        info.type !=
            PROTOCOL_TYPE_CLIENT_ID ||
        info.target_id != 42) {

        printf(
            "Client ID validation: FAIL\n"
        );

        return 1;
    }

    printf(
        "Client ID frame: PASS\n"
    );

    printf(
        "Protocol relay test PASSED\n"
    );

    return 0;
}
