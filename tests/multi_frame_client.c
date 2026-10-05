#include "crypto.h"
#include "key_manager.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 9090

#define FRAME_SIZE \
    (PROTOCOL_HEADER_SIZE + \
     PROTOCOL_MAX_PAYLOAD + \
     CRYPTO_MAC_SIZE)

static int send_all(
    int fd,
    const unsigned char *buffer,
    size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        ssize_t n = send(
            fd,
            buffer + sent,
            length - sent,
            0);

        if (n < 0) {
            if (errno == EINTR)
                continue;

            return -1;
        }

        if (n == 0)
            return -1;

        sent += (size_t)n;
    }

    return 0;
}

static int recv_all(
    int fd,
    unsigned char *buffer,
    size_t length)
{
    size_t received = 0;

    while (received < length) {
        ssize_t n = recv(
            fd,
            buffer + received,
            length - received,
            0);

        if (n < 0) {
            if (errno == EINTR)
                continue;

            return -1;
        }

        if (n == 0)
            return -1;

        received += (size_t)n;
    }

    return 0;
}

static int receive_frame(
    int fd,
    unsigned char *frame,
    size_t capacity,
    size_t *frame_len)
{
    unsigned int ciphertext_len;

    if (recv_all(
            fd,
            frame,
            PROTOCOL_HEADER_SIZE) != 0) {
        return -1;
    }

    memcpy(
        &ciphertext_len,
        frame + 1,
        sizeof(ciphertext_len));

    ciphertext_len = ntohl(ciphertext_len);

    *frame_len =
        PROTOCOL_HEADER_SIZE +
        (size_t)ciphertext_len;

    if (*frame_len > capacity)
        return -1;

    if (recv_all(
            fd,
            frame + PROTOCOL_HEADER_SIZE,
            ciphertext_len) != 0) {
        return -1;
    }

    return 0;
}

int main(void)
{
    int fd;
    struct sockaddr_in address;

    unsigned char key[CRYPTO_KEY_SIZE];

    const char *messages[2] = {
        "First frame",
        "Second frame"
    };

    unsigned char frames[2][FRAME_SIZE];
    size_t frame_lengths[2];

    unsigned char response[FRAME_SIZE];
    unsigned char decrypted[PROTOCOL_MAX_PAYLOAD];

    size_t response_length;
    size_t decrypted_length;

    if (crypto_init() != 0) {
        fprintf(stderr, "Crypto initialization failed\n");
        return EXIT_FAILURE;
    }

    if (key_load(
            "config/shared.key",
            key) != 0) {
        fprintf(stderr, "Key loading failed\n");
        return EXIT_FAILURE;
    }

    for (int i = 0; i < 2; i++) {
        if (protocol_encrypt_message(
                (const unsigned char *)messages[i],
                strlen(messages[i]),
                key,
                frames[i],
                sizeof(frames[i]),
                &frame_lengths[i]) != 0) {

            fprintf(stderr, "Encryption failed\n");
            return EXIT_FAILURE;
        }
    }

    fd = socket(
        AF_INET,
        SOCK_STREAM,
        0);

    if (fd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    memset(
        &address,
        0,
        sizeof(address));

    address.sin_family = AF_INET;
    address.sin_port = htons(SERVER_PORT);

    if (inet_pton(
            AF_INET,
            SERVER_IP,
            &address.sin_addr) != 1) {

        fprintf(stderr, "Invalid server address\n");
        close(fd);
        return EXIT_FAILURE;
    }

    if (connect(
            fd,
            (struct sockaddr *)&address,
            sizeof(address)) < 0) {

        perror("connect");
        close(fd);
        return EXIT_FAILURE;
    }

    printf("Connected to server\n");

    /*
     * Send BOTH encrypted frames on the SAME connection.
     */
    if (send_all(
            fd,
            frames[0],
            frame_lengths[0]) != 0) {

        fprintf(stderr, "Failed to send first frame\n");
        close(fd);
        return EXIT_FAILURE;
    }

    if (send_all(
            fd,
            frames[1],
            frame_lengths[1]) != 0) {

        fprintf(stderr, "Failed to send second frame\n");
        close(fd);
        return EXIT_FAILURE;
    }

    printf("Two encrypted frames sent back-to-back\n");

    /*
     * Receive first response.
     */
    if (receive_frame(
            fd,
            response,
            sizeof(response),
            &response_length) != 0) {

        fprintf(stderr, "Failed to receive first response\n");
        close(fd);
        return EXIT_FAILURE;
    }

    if (protocol_decrypt_message(
            response,
            response_length,
            key,
            decrypted,
            sizeof(decrypted),
            &decrypted_length) != 0) {

        fprintf(stderr, "First response decryption failed\n");
        close(fd);
        return EXIT_FAILURE;
    }

    printf(
        "Response 1: %.*s\n",
        (int)decrypted_length,
        decrypted);

    if (decrypted_length != strlen(messages[0]) ||
        memcmp(
            decrypted,
            messages[0],
            decrypted_length) != 0) {

        printf("First response verification: FAIL\n");
        close(fd);
        return EXIT_FAILURE;
    }

    printf("First response verification: PASS\n");

    /*
     * Receive second response.
     */
    if (receive_frame(
            fd,
            response,
            sizeof(response),
            &response_length) != 0) {

        fprintf(stderr, "Failed to receive second response\n");
        close(fd);
        return EXIT_FAILURE;
    }

    if (protocol_decrypt_message(
            response,
            response_length,
            key,
            decrypted,
            sizeof(decrypted),
            &decrypted_length) != 0) {

        fprintf(stderr, "Second response decryption failed\n");
        close(fd);
        return EXIT_FAILURE;
    }

    printf(
        "Response 2: %.*s\n",
        (int)decrypted_length,
        decrypted);

    if (decrypted_length != strlen(messages[1]) ||
        memcmp(
            decrypted,
            messages[1],
            decrypted_length) != 0) {

        printf("Second response verification: FAIL\n");
        close(fd);
        return EXIT_FAILURE;
    }

    printf("Second response verification: PASS\n");

    printf("Multi-frame test PASSED\n");

    close(fd);

    return EXIT_SUCCESS;
}
