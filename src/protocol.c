#include "protocol.h"

#include <string.h>

static void write_u32(
    unsigned char *buffer,
    uint32_t value
)
{
    buffer[0] = (unsigned char)(
        (value >> 24) & 0xff
    );

    buffer[1] = (unsigned char)(
        (value >> 16) & 0xff
    );

    buffer[2] = (unsigned char)(
        (value >> 8) & 0xff
    );

    buffer[3] = (unsigned char)(
        value & 0xff
    );
}

static uint32_t read_u32(
    const unsigned char *buffer
)
{
    return
        ((uint32_t)buffer[0] << 24) |
        ((uint32_t)buffer[1] << 16) |
        ((uint32_t)buffer[2] << 8) |
        ((uint32_t)buffer[3]);
}

static void write_u64(
    unsigned char *buffer,
    uint64_t value
)
{
    for (int i = 0; i < 8; i++) {
        buffer[i] =
            (unsigned char)(
                (value >> (56 - i * 8)) &
                0xff
            );
    }
}

static uint64_t read_u64(
    const unsigned char *buffer
)
{
    uint64_t value = 0;

    for (int i = 0; i < 8; i++) {
        value =
            (value << 8) |
            buffer[i];
    }

    return value;
}

static void build_aad(
    const unsigned char *header,
    unsigned char *aad
)
{
    /*
     * Authenticate everything except the nonce.
     *
     * The nonce is itself an input to the AEAD
     * construction and therefore is authenticated
     * through the authentication tag.
     */
    memcpy(
        aad,
        header,
        22
    );

    memcpy(
        aad + 22,
        header + 42,
        4
    );
}

int protocol_build_client_id_frame(
    uint32_t client_id,
    unsigned char *frame,
    size_t frame_capacity,
    size_t *frame_length
)
{
    if (frame == NULL ||
        frame_length == NULL ||
        frame_capacity < PROTOCOL_HEADER_SIZE) {

        return -1;
    }

    memset(
        frame,
        0,
        PROTOCOL_HEADER_SIZE
    );

    frame[0] = PROTOCOL_VERSION;
    frame[1] = PROTOCOL_TYPE_CLIENT_ID;

    write_u32(
        frame + 2,
        0
    );

    write_u32(
        frame + 6,
        client_id
    );

    write_u64(
        frame + 10,
        0
    );

    write_u32(
        frame + 18,
        0
    );

    /*
     * Nonce remains zero for control frame.
     */
    memset(
        frame + 22,
        0,
        CRYPTO_NONCE_SIZE
    );

    *frame_length =
        PROTOCOL_HEADER_SIZE;

    return 0;
}

int protocol_build_message_frame(
    const unsigned char *key,
    uint32_t sender_id,
    uint32_t target_id,
    uint64_t sequence,
    const unsigned char *plaintext,
    size_t plaintext_length,
    unsigned char *frame,
    size_t frame_capacity,
    size_t *frame_length
)
{
    size_t ciphertext_length;
    size_t total_length;

    unsigned char aad[26];

    if (key == NULL ||
        plaintext == NULL ||
        frame == NULL ||
        frame_length == NULL) {

        return -1;
    }

    if (plaintext_length >
        PROTOCOL_MAX_PAYLOAD) {

        return -1;
    }

    ciphertext_length =
        plaintext_length +
        CRYPTO_MAC_SIZE;

    total_length =
        PROTOCOL_HEADER_SIZE +
        ciphertext_length;

    if (frame_capacity < total_length) {
        return -1;
    }

    memset(
        frame,
        0,
        PROTOCOL_HEADER_SIZE
    );

    frame[0] = PROTOCOL_VERSION;
    frame[1] = PROTOCOL_TYPE_MESSAGE;

    write_u32(
        frame + 2,
        sender_id
    );

    write_u32(
        frame + 6,
        target_id
    );

    write_u64(
        frame + 10,
        sequence
    );

    write_u32(
        frame + 18,
        (uint32_t)ciphertext_length
    );

    if (crypto_generate_nonce(
            frame + 22) != 0) {

        return -1;
    }

    build_aad(
        frame,
        aad
    );

    if (crypto_encrypt(
            key,
            frame + 22,
            plaintext,
            plaintext_length,
            aad,
            sizeof(aad),
            frame + PROTOCOL_HEADER_SIZE,
            &ciphertext_length) != 0) {

        return -1;
    }

    /*
     * The calculated ciphertext length must match
     * what was placed in the header.
     */
    if (ciphertext_length !=
        (plaintext_length + CRYPTO_MAC_SIZE)) {

        return -1;
    }

    *frame_length =
        PROTOCOL_HEADER_SIZE +
        ciphertext_length;

    return 0;
}

int protocol_parse_frame(
    const unsigned char *frame,
    size_t frame_length,
    protocol_frame_info *info
)
{
    uint32_t ciphertext_length;

    if (frame == NULL ||
        info == NULL) {

        return -1;
    }

    if (frame_length <
        PROTOCOL_HEADER_SIZE) {

        return -1;
    }

    if (frame[0] != PROTOCOL_VERSION) {
        return -1;
    }

    info->version = frame[0];
    info->type = frame[1];

    info->sender_id =
        read_u32(frame + 2);

    info->target_id =
        read_u32(frame + 6);

    info->sequence =
        read_u64(frame + 10);

    ciphertext_length =
        read_u32(frame + 18);

    info->ciphertext_length =
        ciphertext_length;

    memcpy(
        info->nonce,
        frame + 22,
        CRYPTO_NONCE_SIZE
    );

    if (info->type ==
        PROTOCOL_TYPE_CLIENT_ID) {

        if (ciphertext_length != 0) {
            return -1;
        }

        if (frame_length !=
            PROTOCOL_HEADER_SIZE) {

            return -1;
        }

        return 0;
    }

    if (info->type !=
        PROTOCOL_TYPE_MESSAGE) {

        return -1;
    }

    if (ciphertext_length <
        CRYPTO_MAC_SIZE) {

        return -1;
    }

    if (ciphertext_length >
        PROTOCOL_MAX_PAYLOAD +
        CRYPTO_MAC_SIZE) {

        return -1;
    }

    if (frame_length !=
        PROTOCOL_HEADER_SIZE +
        ciphertext_length) {

        return -1;
    }

    return 0;
}

int protocol_decrypt_message(
    const unsigned char *key,
    const unsigned char *frame,
    size_t frame_length,
    unsigned char *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_length
)
{
    protocol_frame_info info;

    unsigned char aad[26];

    if (key == NULL ||
        frame == NULL ||
        plaintext == NULL ||
        plaintext_length == NULL) {

        return -1;
    }

    if (protocol_parse_frame(
            frame,
            frame_length,
            &info) != 0) {

        return -1;
    }

    if (info.type !=
        PROTOCOL_TYPE_MESSAGE) {

        return -1;
    }

    if (info.ciphertext_length <
        CRYPTO_MAC_SIZE) {

        return -1;
    }

    if (plaintext_capacity <
        info.ciphertext_length -
        CRYPTO_MAC_SIZE) {

        return -1;
    }

    build_aad(
        frame,
        aad
    );

    return crypto_decrypt(
        key,
        info.nonce,
        frame + PROTOCOL_HEADER_SIZE,
        info.ciphertext_length,
        aad,
        sizeof(aad),
        plaintext,
        plaintext_length
    );
}
