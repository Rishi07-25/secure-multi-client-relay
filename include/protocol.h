#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "crypto.h"

#include <stddef.h>
#include <stdint.h>

#define PROTOCOL_VERSION 1

#define PROTOCOL_TYPE_CLIENT_ID 1
#define PROTOCOL_TYPE_MESSAGE   2

#define PROTOCOL_BROADCAST_ID 0

#define PROTOCOL_MAX_PAYLOAD 4096

/*
 * version       1
 * type          1
 * sender_id     4
 * target_id     4
 * sequence      8
 * ciphertext    4
 * nonce        24
 *
 * Total = 46 bytes
 */
#define PROTOCOL_HEADER_SIZE 46

#define PROTOCOL_MAX_FRAME_SIZE \
    (PROTOCOL_HEADER_SIZE + \
     PROTOCOL_MAX_PAYLOAD + \
     CRYPTO_MAC_SIZE)

typedef struct {
    uint8_t version;
    uint8_t type;

    uint32_t sender_id;
    uint32_t target_id;

    uint64_t sequence;

    uint32_t ciphertext_length;

    unsigned char nonce[
        CRYPTO_NONCE_SIZE
    ];

} protocol_frame_info;

int protocol_build_client_id_frame(
    uint32_t client_id,
    unsigned char *frame,
    size_t frame_capacity,
    size_t *frame_length
);

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
);

int protocol_parse_frame(
    const unsigned char *frame,
    size_t frame_length,
    protocol_frame_info *info
);

int protocol_decrypt_message(
    const unsigned char *key,
    const unsigned char *frame,
    size_t frame_length,
    unsigned char *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_length
);

#endif
