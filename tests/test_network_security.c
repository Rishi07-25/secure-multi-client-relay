#include "crypto.h"
#include "key_manager.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 9090

#define FRAME_BUFFER_SIZE \
    (PROTOCOL_HEADER_SIZE + \
     PROTOCOL_MAX_PAYLOAD + \
     CRYPTO_MAC_SIZE)

static int connect_to_server(void)
{
    int socket_fd;
    struct sockaddr_in address;

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (socket_fd < 0) {
        return -1;
    }

    memset(&address, 0, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_port = htons(SERVER_PORT);

    if (inet_pton(
            AF_INET,
            SERVER_IP,
            &address.sin_addr) != 1) {

        close(socket_fd);
        return -1;
    }

    if (connect(
            socket_fd,
            (struct sockaddr *)&address,
            sizeof(address)) < 0) {

        close(socket_fd);
        return -1;
    }

    return socket_fd;
}

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

static void test_invalid_version(void)
{
    int fd;
    unsigned char frame[PROTOCOL_HEADER_SIZE];

    memset(frame, 0, sizeof(frame));

    frame[0] = 99;

    fd = connect_to_server();

    if (fd < 0) {
        printf("Invalid version test: CONNECTION FAILED\n");
        return;
    }

    send_all(fd, frame, sizeof(frame));

    close(fd);

    printf("Invalid version test: SENT\n");
}

static void test_invalid_length(void)
{
    int fd;
    unsigned char frame[PROTOCOL_HEADER_SIZE];

    memset(frame, 0, sizeof(frame));

    frame[0] = PROTOCOL_VERSION;

    /*
     * Deliberately claim a ciphertext length larger
     * than the protocol permits.
     */
    unsigned int bad_length =
        htonl(PROTOCOL_MAX_PAYLOAD +
              CRYPTO_MAC_SIZE +
              1);

    memcpy(
        frame + 1,
        &bad_length,
        sizeof(bad_length));

    fd = connect_to_server();

    if (fd < 0) {
        printf("Invalid length test: CONNECTION FAILED\n");
        return;
    }

    send_all(fd, frame, sizeof(frame));

    close(fd);

    printf("Invalid length test: SENT\n");
}

static void test_tampered_ciphertext(
    const unsigned char key[CRYPTO_KEY_SIZE])
{
    int fd;

    unsigned char frame[
        FRAME_BUFFER_SIZE
    ];

    size_t frame_len;

    const unsigned char message[] =
        "tamper test";

    if (protocol_encrypt_message(
            message,
            sizeof(message) - 1,
            key,
            frame,
            sizeof(frame),
            &frame_len) != 0) {

        printf("Tampered ciphertext test: ENCRYPTION FAILED\n");
        return;
    }

    /*
     * Change one byte inside the ciphertext.
     * The authentication tag should no longer validate.
     */
    frame[PROTOCOL_HEADER_SIZE] ^= 0x01;

    fd = connect_to_server();

    if (fd < 0) {
        printf("Tampered ciphertext test: CONNECTION FAILED\n");
        return;
    }

send_all(fd, frame, frame_len);

/*
 * Keep the connection open long enough for
 * the server worker to process the tampered frame.
 */
sleep(1);

close(fd);

printf("Tampered ciphertext test: SENT\n");
}

int main(void)
{
    unsigned char key[CRYPTO_KEY_SIZE];

    if (crypto_init() != 0) {
        printf("Crypto initialization: FAIL\n");
        return 1;
    }

    if (key_load(
            "config/shared.key",
            key) != 0) {

        printf("Key loading: FAIL\n");
        return 1;
    }

    printf("Network security tests\n");
    printf("======================\n");

    test_invalid_version();

    test_invalid_length();

    test_tampered_ciphertext(key);

    printf("\nSecurity test frames sent.\n");
    printf("Check the server output for rejection messages.\n");

    return 0;
}
