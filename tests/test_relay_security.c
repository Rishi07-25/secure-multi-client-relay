#define _POSIX_C_SOURCE 200809L
#include "crypto.h"
#include "key_manager.h"
#include "protocol.h"

#include <time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 9090

#define TEST_TIMEOUT_MS 3000
#define FIRST_MESSAGE_SEQUENCE 1ULL


static void write_u32_be(
    unsigned char *buffer,
    uint32_t value
)
{
    buffer[0] = (unsigned char)(value >> 24);
    buffer[1] = (unsigned char)(value >> 16);
    buffer[2] = (unsigned char)(value >> 8);
    buffer[3] = (unsigned char)value;
}


static int send_all(
    int fd,
    const unsigned char *data,
    size_t length
)
{
    size_t sent = 0;

    while (sent < length) {

        ssize_t result =
            send(
                fd,
                data + sent,
                length - sent,
                0
            );

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
    int fd,
    unsigned char *buffer,
    size_t length
)
{
    size_t received = 0;

    while (received < length) {

        ssize_t result =
            recv(
                fd,
                buffer + received,
                length - received,
                0
            );

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


static int wait_for_connection_close(
    int fd,
    int timeout_ms
)
{
    struct pollfd descriptor;

    memset(
        &descriptor,
        0,
        sizeof(descriptor)
    );

    descriptor.fd = fd;
    descriptor.events =
        POLLIN | POLLHUP | POLLERR;

    int result =
        poll(
            &descriptor,
            1,
            timeout_ms
        );

    if (result < 0) {

        if (errno == EINTR) {
            return wait_for_connection_close(
                fd,
                timeout_ms
            );
        }

        return -1;
    }

    if (result == 0) {
        return 0;
    }

    unsigned char buffer[256];

    for (;;) {

        ssize_t received =
            recv(
                fd,
                buffer,
                sizeof(buffer),
                0
            );

        if (received == 0) {
            return 1;
        }

        if (received < 0) {

            if (errno == EINTR) {
                continue;
            }

            if (errno == ECONNRESET) {
                return 1;
            }

            return -1;
        }

        descriptor.events =
            POLLIN | POLLHUP | POLLERR;

        result =
            poll(
                &descriptor,
                1,
                timeout_ms
            );

        if (result <= 0) {
            return 0;
        }
    }
}


static int open_client(
    uint32_t *client_id
)
{
    int fd;

    struct sockaddr_in address;

    unsigned char frame[
        PROTOCOL_HEADER_SIZE
    ];

    protocol_frame_info info;

    fd =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );

    if (fd < 0) {
        return -1;
    }

    memset(
        &address,
        0,
        sizeof(address)
    );

    address.sin_family =
        AF_INET;

    address.sin_port =
        htons(SERVER_PORT);

    if (inet_pton(
            AF_INET,
            SERVER_IP,
            &address.sin_addr) != 1) {

        close(fd);
        return -1;
    }

    if (connect(
            fd,
            (struct sockaddr *)&address,
            sizeof(address)) < 0) {

        close(fd);
        return -1;
    }

    /*
     * The server immediately sends the
     * client-ID control frame.
     */
    if (recv_all(
            fd,
            frame,
            sizeof(frame)) != 0) {

        close(fd);
        return -1;
    }

    if (protocol_parse_frame(
            frame,
            sizeof(frame),
            &info) != 0) {

        close(fd);
        return -1;
    }

    if (info.type !=
        PROTOCOL_TYPE_CLIENT_ID) {

        close(fd);
        return -1;
    }

    *client_id =
        info.target_id;

    return fd;
}


static int build_test_frame(
    const unsigned char *key,
    uint32_t sender_id,
    uint32_t target_id,
    uint64_t sequence,
    unsigned char *frame,
    size_t *frame_length
)
{
    static const unsigned char plaintext[] =
        "security-test-message";

    return protocol_build_message_frame(
        key,
        sender_id,
        target_id,
        sequence,
        plaintext,
        sizeof(plaintext) - 1,
        frame,
        PROTOCOL_MAX_FRAME_SIZE,
        frame_length
    );
}


static int test_invalid_version(
    const unsigned char *key
)
{
    uint32_t client_id;

    int fd =
        open_client(
            &client_id
        );

    if (fd < 0) {
        return -1;
    }

    unsigned char frame[
        PROTOCOL_MAX_FRAME_SIZE
    ];

    size_t frame_length = 0;

    if (build_test_frame(
            key,
            client_id,
            PROTOCOL_BROADCAST_ID,
            FIRST_MESSAGE_SEQUENCE,
            frame,
            &frame_length) != 0) {

        close(fd);
        return -1;
    }

    /*
     * Change the protocol version.
     */
    frame[0] = 99;

    /*
     * The server must reject the frame before
     * it reaches the relay worker.
     */
    if (send_all(
            fd,
            frame,
            frame_length) != 0) {

        close(fd);
        return -1;
    }

    int closed =
        wait_for_connection_close(
            fd,
            TEST_TIMEOUT_MS
        );

    close(fd);

    return closed == 1 ? 0 : -1;
}


static int test_invalid_length(
    const unsigned char *key
)
{
    uint32_t client_id;

    int fd =
        open_client(
            &client_id
        );

    if (fd < 0) {
        return -1;
    }

    unsigned char frame[
        PROTOCOL_MAX_FRAME_SIZE
    ];

    size_t frame_length = 0;

    if (build_test_frame(
            key,
            client_id,
            PROTOCOL_BROADCAST_ID,
            FIRST_MESSAGE_SEQUENCE,
            frame,
            &frame_length) != 0) {

        close(fd);
        return -1;
    }

    /*
     * Set the declared ciphertext length to zero.
     * The protocol parser must reject this because
     * an encrypted message must contain its MAC.
     */
    write_u32_be(
        frame + 18,
        0
    );

    if (send_all(
            fd,
            frame,
            PROTOCOL_HEADER_SIZE) != 0) {

        close(fd);
        return -1;
    }

    int closed =
        wait_for_connection_close(
            fd,
            TEST_TIMEOUT_MS
        );

    close(fd);

    return closed == 1 ? 0 : -1;
}


static int test_sender_spoofing(
    const unsigned char *key
)
{
    uint32_t client_id;

    int fd =
        open_client(
            &client_id
        );

    if (fd < 0) {
        return -1;
    }

    unsigned char frame[
        PROTOCOL_MAX_FRAME_SIZE
    ];

    size_t frame_length = 0;

    /*
     * Claim to be a different client.
     */
    uint32_t spoofed_sender =
        client_id + 1000;

    if (build_test_frame(
            key,
            spoofed_sender,
            PROTOCOL_BROADCAST_ID,
            FIRST_MESSAGE_SEQUENCE,
            frame,
            &frame_length) != 0) {

        close(fd);
        return -1;
    }

    if (send_all(
            fd,
            frame,
            frame_length) != 0) {

        close(fd);
        return -1;
    }

    int closed =
        wait_for_connection_close(
            fd,
            TEST_TIMEOUT_MS
        );

    close(fd);

    return closed == 1 ? 0 : -1;
}


static int test_replay(
    const unsigned char *key
)
{
    uint32_t client_id;

    int fd =
        open_client(
            &client_id
        );

    if (fd < 0) {
        return -1;
    }

    unsigned char frame[
        PROTOCOL_MAX_FRAME_SIZE
    ];

    size_t frame_length = 0;

    /*
     * Sequence 1 is the first valid message.
     */
    if (build_test_frame(
            key,
            client_id,
            PROTOCOL_BROADCAST_ID,
            FIRST_MESSAGE_SEQUENCE,
            frame,
            &frame_length) != 0) {

        close(fd);
        return -1;
    }

    /*
     * First transmission must be accepted.
     */
    if (send_all(
            fd,
            frame,
            frame_length) != 0) {

        close(fd);
        return -1;
    }

    /*
     * Give the server time to process the first
     * frame and advance its expected sequence to 2.
     */
    struct timespec delay;

    delay.tv_sec = 0;
    delay.tv_nsec = 100000000L;

    nanosleep(
        &delay,
        NULL
    );

    /*
     * Replay exactly the same sequence-1 frame.
     *
     * The server has already accepted sequence 1,
     * so sequence 1 is now a replay and must cause
     * the connection to close.
     */
    if (send_all(
            fd,
            frame,
            frame_length) != 0) {

        /*
         * If the server closed the socket before the
         * second send completed, replay protection
         * has triggered successfully.
         */
        close(fd);
        return 0;
    }

    /*
     * The server sends no rejection response.
     * We only need to observe the connection closing.
     */
    int closed =
        wait_for_connection_close(
            fd,
            TEST_TIMEOUT_MS
        );

    close(fd);

    return closed == 1 ? 0 : -1;
}


int main(void)
{
    unsigned char key[
        CRYPTO_KEY_SIZE
    ];

    int failures = 0;

    printf(
        "\n"
        "================================\n"
        " Secure Relay Security Test Suite\n"
        "================================\n\n"
    );

    if (crypto_init() != 0) {

        fprintf(
            stderr,
            "Crypto initialization failed\n"
        );

        return EXIT_FAILURE;
    }

    if (key_load(
            "config/shared.key",
            key) != 0) {

        fprintf(
            stderr,
            "Failed to load config/shared.key\n"
        );

        return EXIT_FAILURE;
    }

    /*
     * Test 1
     */
    if (test_invalid_version(key) == 0) {

        printf(
            "Invalid version: PASS\n"
        );

    } else {

        printf(
            "Invalid version: FAIL\n"
        );

        failures++;
    }

    /*
     * Test 2
     */
    if (test_invalid_length(key) == 0) {

        printf(
            "Invalid length: PASS\n"
        );

    } else {

        printf(
            "Invalid length: FAIL\n"
        );

        failures++;
    }

    /*
     * Test 3
     */
    if (test_sender_spoofing(key) == 0) {

        printf(
            "Sender spoofing: PASS\n"
        );

    } else {

        printf(
            "Sender spoofing: FAIL\n"
        );

        failures++;
    }

    /*
     * Test 4
     */
    if (test_replay(key) == 0) {

        printf(
            "Replay protection: PASS\n"
        );

    } else {

        printf(
            "Replay protection: FAIL\n"
        );

        failures++;
    }

    printf(
        "\n================================\n"
    );

    if (failures == 0) {

        printf(
            "SECURITY TEST SUITE PASSED\n"
        );

        printf(
            "================================\n"
        );

        return EXIT_SUCCESS;
    }

    printf(
        "SECURITY TEST SUITE FAILED: %d issue(s)\n",
        failures
    );

    printf(
        "================================\n"
    );

    return EXIT_FAILURE;
}
