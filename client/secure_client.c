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

static int send_all(
    int socket_fd,
    const unsigned char *buffer,
    size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        ssize_t result = send(
            socket_fd,
            buffer + sent,
            length - sent,
            0);

        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }

            return -1;
        }

        if (result == 0) {
            return -1;
        }

        sent += (size_t)result;
    }

    return 0;
}

static int recv_all(
    int socket_fd,
    unsigned char *buffer,
    size_t length)
{
    size_t received = 0;

    while (received < length) {
        ssize_t result = recv(
            socket_fd,
            buffer + received,
            length - received,
            0);

        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }

            return -1;
        }

        if (result == 0) {
            return -1;
        }

        received += (size_t)result;
    }

    return 0;
}

int main(void)
{
    int socket_fd;
    struct sockaddr_in server_address;

    unsigned char key[CRYPTO_KEY_SIZE];

    unsigned char plaintext[PROTOCOL_MAX_PAYLOAD];

    unsigned char encrypted_frame[
        PROTOCOL_HEADER_SIZE +
        PROTOCOL_MAX_PAYLOAD +
        CRYPTO_MAC_SIZE
    ];

    unsigned char response_frame[
        PROTOCOL_HEADER_SIZE +
        PROTOCOL_MAX_PAYLOAD +
        CRYPTO_MAC_SIZE
    ];

    unsigned char decrypted_response[
        PROTOCOL_MAX_PAYLOAD
    ];

    size_t plaintext_len;
    size_t frame_len;
    size_t response_len;
    size_t decrypted_len;

    unsigned int ciphertext_len;

    const char *message = "Hello secure relay";

    if (crypto_init() != 0) {
        fprintf(stderr, "Crypto initialization failed\n");
        return EXIT_FAILURE;
    }

    if (key_load("config/shared.key", key) != 0) {
        fprintf(stderr, "Failed to load shared key\n");
        return EXIT_FAILURE;
    }

    plaintext_len = strlen(message);

    memcpy(
        plaintext,
        message,
        plaintext_len);

    if (protocol_encrypt_message(
            plaintext,
            plaintext_len,
            key,
            encrypted_frame,
            sizeof(encrypted_frame),
            &frame_len) != 0) {

        fprintf(stderr, "Encryption failed\n");
        return EXIT_FAILURE;
    }

    printf("Plaintext: %s\n", message);
    printf("Encrypted frame size: %zu bytes\n", frame_len);

    socket_fd = socket(
        AF_INET,
        SOCK_STREAM,
        0);

    if (socket_fd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    memset(
        &server_address,
        0,
        sizeof(server_address));

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(SERVER_PORT);

    if (inet_pton(
            AF_INET,
            SERVER_IP,
            &server_address.sin_addr) != 1) {

        fprintf(stderr, "Invalid server address\n");
        close(socket_fd);
        return EXIT_FAILURE;
    }

    if (connect(
            socket_fd,
            (struct sockaddr *)&server_address,
            sizeof(server_address)) < 0) {

        perror("connect");
        close(socket_fd);
        return EXIT_FAILURE;
    }

    printf("Connected to server\n");

    /*
     * Send exactly one complete encrypted frame.
     */
    if (send_all(
            socket_fd,
            encrypted_frame,
            frame_len) != 0) {

        fprintf(
            stderr,
            "Failed to send encrypted frame\n");

        close(socket_fd);
        return EXIT_FAILURE;
    }

    printf("Encrypted frame sent\n");

    /*
     * Receive the fixed 29-byte protocol header first.
     */
    if (recv_all(
            socket_fd,
            response_frame,
            PROTOCOL_HEADER_SIZE) != 0) {

        fprintf(
            stderr,
            "Failed to receive protocol header\n");

        close(socket_fd);
        return EXIT_FAILURE;
    }

    /*
     * Extract ciphertext length.
     */
    memcpy(
        &ciphertext_len,
        response_frame + 1,
        sizeof(ciphertext_len));

    ciphertext_len = ntohl(ciphertext_len);

    response_len =
        PROTOCOL_HEADER_SIZE +
        ciphertext_len;

    if (response_len > sizeof(response_frame)) {
        fprintf(
            stderr,
            "Response frame too large\n");

        close(socket_fd);
        return EXIT_FAILURE;
    }

    /*
     * Receive the encrypted payload.
     */
    if (recv_all(
            socket_fd,
            response_frame + PROTOCOL_HEADER_SIZE,
            ciphertext_len) != 0) {

        fprintf(
            stderr,
            "Failed to receive response payload\n");

        close(socket_fd);
        return EXIT_FAILURE;
    }

    printf("Encrypted response received\n");

    /*
     * Decrypt the response.
     */
    if (protocol_decrypt_message(
            response_frame,
            response_len,
            key,
            decrypted_response,
            sizeof(decrypted_response),
            &decrypted_len) != 0) {

        fprintf(
            stderr,
            "Response decryption failed\n");

        close(socket_fd);
        return EXIT_FAILURE;
    }

    printf(
        "Decrypted response: %.*s\n",
        (int)decrypted_len,
        decrypted_response);

    /*
     * Verify that the response matches the
     * original plaintext.
     */
    if (decrypted_len == plaintext_len &&
        memcmp(
            decrypted_response,
            plaintext,
            plaintext_len) == 0) {

        printf("Secure echo verification: PASS\n");
    } else {
        printf("Secure echo verification: FAIL\n");
    }

    close(socket_fd);

    return EXIT_SUCCESS;
}
