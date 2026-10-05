#include "crypto.h"
#include "key_manager.h"
#include "protocol.h"

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

#define TEST_TIMEOUT_MS 10000
#define MESSAGES_PER_CLIENT 3

#define TEST_CLIENTS_10 10
#define TEST_CLIENTS_50 50
#define TEST_CLIENTS_100 100

/*
 * The production relay server initializes replay protection such that
 * the first valid application message uses sequence number 1.
 */
#define FIRST_MESSAGE_SEQUENCE 1ULL

typedef struct {
    int fd;
    uint32_t id;
} stress_client_t;

static int send_all(
    int fd,
    const unsigned char *data,
    size_t length
)
{
    size_t sent = 0;

    while (sent < length) {
        ssize_t result = send(
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
        ssize_t result = recv(
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

static int recv_with_timeout(
    int fd,
    unsigned char *buffer,
    size_t length,
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
        POLLIN |
        POLLHUP |
        POLLERR;

    int result = poll(
        &descriptor,
        1,
        timeout_ms
    );

    if (result < 0) {
        if (errno == EINTR) {
            return recv_with_timeout(
                fd,
                buffer,
                length,
                timeout_ms
            );
        }

        return -1;
    }

    if (result == 0) {
        return -2;
    }

    return recv_all(
        fd,
        buffer,
        length
    );
}

/*
 * Receive one complete protocol frame.
 *
 * Important:
 * protocol_parse_frame() validates the complete frame, not merely
 * the header. Therefore the ciphertext must be received before parsing.
 *
 * Current protocol layout stores ciphertext length at bytes 18..21
 * in network byte order.
 */
static int receive_frame(
    int fd,
    unsigned char *frame,
    size_t capacity,
    size_t *frame_length
)
{
    unsigned char header[PROTOCOL_HEADER_SIZE];

    if (recv_with_timeout(
            fd,
            header,
            sizeof(header),
            TEST_TIMEOUT_MS) != 0) {

        return -1;
    }

    /*
     * Ciphertext length is a 32-bit network-order field at
     * header offsets 18..21.
     */
    uint32_t ciphertext_length =
        ((uint32_t)header[18] << 24) |
        ((uint32_t)header[19] << 16) |
        ((uint32_t)header[20] << 8) |
        (uint32_t)header[21];

    size_t total_length =
        PROTOCOL_HEADER_SIZE +
        (size_t)ciphertext_length;

    if (total_length > capacity) {
        return -1;
    }

    if (total_length > PROTOCOL_MAX_FRAME_SIZE) {
        return -1;
    }

    memcpy(
        frame,
        header,
        PROTOCOL_HEADER_SIZE
    );

    if (ciphertext_length > 0) {
        if (recv_all(
                fd,
                frame + PROTOCOL_HEADER_SIZE,
                ciphertext_length) != 0) {

            return -1;
        }
    }

    /*
     * Only parse after the complete frame has been received.
     */
    protocol_frame_info info;

    if (protocol_parse_frame(
            frame,
            total_length,
            &info) != 0) {

        return -1;
    }

    *frame_length = total_length;

    return 0;
}

static int connect_client(
    const unsigned char *key,
    stress_client_t *client
)
{
    (void)key;

    int fd = socket(
        AF_INET,
        SOCK_STREAM,
        0
    );

    if (fd < 0) {
        return -1;
    }

    struct sockaddr_in address;

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

    unsigned char id_frame[
        PROTOCOL_HEADER_SIZE
    ];

    if (recv_all(
            fd,
            id_frame,
            sizeof(id_frame)) != 0) {

        close(fd);
        return -1;
    }

    protocol_frame_info info;

    if (protocol_parse_frame(
            id_frame,
            sizeof(id_frame),
            &info) != 0) {

        close(fd);
        return -1;
    }

    if (info.type !=
        PROTOCOL_TYPE_CLIENT_ID) {

        close(fd);
        return -1;
    }

    client->fd = fd;
    client->id = info.target_id;

    return 0;
}

static void close_clients(
    stress_client_t *clients,
    size_t count
)
{
    for (size_t i = 0;
         i < count;
         i++) {

        if (clients[i].fd >= 0) {
            shutdown(
                clients[i].fd,
                SHUT_RDWR
            );

            close(
                clients[i].fd
            );

            clients[i].fd = -1;
        }
    }
}

static int send_test_messages(
    const unsigned char *key,
    stress_client_t *clients,
    size_t count
)
{
    unsigned char frame[
        PROTOCOL_MAX_FRAME_SIZE
    ];

    /*
     * Every client sends to the next client.
     *
     * client 0 -> client 1
     * client 1 -> client 2
     * ...
     * client N -> client 0
     */

    for (size_t i = 0;
         i < count;
         i++) {

        size_t target_index =
            (i + 1) % count;

        for (uint64_t message_index = 0;
             message_index < MESSAGES_PER_CLIENT;
             message_index++) {

            uint64_t sequence =
                FIRST_MESSAGE_SEQUENCE +
                message_index;

            char plaintext[128];

            int plaintext_length =
                snprintf(
                    plaintext,
                    sizeof(plaintext),
                    "stress-client-%u-message-%llu",
                    clients[i].id,
                    (unsigned long long)
                        message_index
                );

            if (plaintext_length < 0) {
                return -1;
            }

            size_t frame_length = 0;

            if (protocol_build_message_frame(
                    key,
                    clients[i].id,
                    clients[target_index].id,
                    sequence,
                    (const unsigned char *)
                        plaintext,
                    (size_t)plaintext_length,
                    frame,
                    sizeof(frame),
                    &frame_length) != 0) {

                return -1;
            }

            if (send_all(
                    clients[i].fd,
                    frame,
                    frame_length) != 0) {

                return -1;
            }
        }
    }

    return 0;
}

static int verify_received_messages(
    const unsigned char *key,
    stress_client_t *clients,
    size_t count
)
{
    unsigned char frame[
        PROTOCOL_MAX_FRAME_SIZE
    ];

    unsigned char plaintext[
        PROTOCOL_MAX_PAYLOAD
    ];

    /*
     * Each client should receive exactly
     * MESSAGES_PER_CLIENT frames from the
     * previous client.
     */

    for (size_t i = 0;
         i < count;
         i++) {

        size_t expected_sender_index;

        if (i == 0) {
            expected_sender_index =
                count - 1;
        } else {
            expected_sender_index =
                i - 1;
        }

        for (uint64_t message_index = 0;
             message_index < MESSAGES_PER_CLIENT;
             message_index++) {

            uint64_t expected_sequence =
                FIRST_MESSAGE_SEQUENCE +
                message_index;

            size_t frame_length = 0;

            if (receive_frame(
                    clients[i].fd,
                    frame,
                    sizeof(frame),
                    &frame_length) != 0) {

                fprintf(
                    stderr,
                    "Receive failure: "
                    "client %u expected "
                    "message %llu\n",
                    clients[i].id,
                    (unsigned long long)
                        message_index
                );

                return -1;
            }

            protocol_frame_info info;

            if (protocol_parse_frame(
                    frame,
                    frame_length,
                    &info) != 0) {

                fprintf(
                    stderr,
                    "Protocol parse failure "
                    "at client %u\n",
                    clients[i].id
                );

                return -1;
            }

            if (info.type !=
                PROTOCOL_TYPE_MESSAGE) {

                fprintf(
                    stderr,
                    "Unexpected frame type "
                    "at client %u\n",
                    clients[i].id
                );

                return -1;
            }

            if (info.sender_id !=
                clients[expected_sender_index].id) {

                fprintf(
                    stderr,
                    "Sender mismatch: "
                    "receiver=%u expected=%u "
                    "actual=%u\n",
                    clients[i].id,
                    clients[expected_sender_index].id,
                    info.sender_id
                );

                return -1;
            }

            if (info.target_id !=
                clients[i].id) {

                fprintf(
                    stderr,
                    "Target mismatch: "
                    "receiver=%u frame_target=%u\n",
                    clients[i].id,
                    info.target_id
                );

                return -1;
            }

            if (info.sequence !=
                expected_sequence) {

                fprintf(
                    stderr,
                    "Sequence mismatch: "
                    "receiver=%u expected=%llu "
                    "actual=%llu\n",
                    clients[i].id,
                    (unsigned long long)
                        expected_sequence,
                    (unsigned long long)
                        info.sequence
                );

                return -1;
            }

            size_t plaintext_length = 0;

            if (protocol_decrypt_message(
                    key,
                    frame,
                    frame_length,
                    plaintext,
                    sizeof(plaintext),
                    &plaintext_length) != 0) {

                fprintf(
                    stderr,
                    "Decryption failure: "
                    "receiver=%u sequence=%llu\n",
                    clients[i].id,
                    (unsigned long long)
                        expected_sequence
                );

                return -1;
            }

            char expected_plaintext[128];

            int expected_length =
                snprintf(
                    expected_plaintext,
                    sizeof(expected_plaintext),
                    "stress-client-%u-message-%llu",
                    clients[expected_sender_index].id,
                    (unsigned long long)
                        message_index
                );

            if (expected_length < 0 ||
                plaintext_length !=
                    (size_t)expected_length ||
                memcmp(
                    plaintext,
                    expected_plaintext,
                    (size_t)expected_length
                ) != 0) {

                fprintf(
                    stderr,
                    "Payload mismatch: "
                    "receiver=%u sequence=%llu\n",
                    clients[i].id,
                    (unsigned long long)
                        expected_sequence
                );

                return -1;
            }
        }
    }

    return 0;
}

static int run_stress_test(
    const unsigned char *key,
    size_t client_count
)
{
    printf(
        "\n--------------------------------\n"
    );

    printf(
        "Running %zu-client relay test\n",
        client_count
    );

    printf(
        "Messages per client: %d\n",
        MESSAGES_PER_CLIENT
    );

    printf(
        "Total messages: %zu\n",
        client_count *
            MESSAGES_PER_CLIENT
    );

    printf(
        "--------------------------------\n"
    );

    stress_client_t *clients =
        calloc(
            client_count,
            sizeof(stress_client_t)
        );

    if (clients == NULL) {
        fprintf(
            stderr,
            "Failed to allocate clients\n"
        );

        return -1;
    }

    for (size_t i = 0;
         i < client_count;
         i++) {

        clients[i].fd = -1;

        if (connect_client(
                key,
                &clients[i]) != 0) {

            fprintf(
                stderr,
                "Failed to connect client %zu\n",
                i + 1
            );

            close_clients(
                clients,
                i
            );

            free(clients);

            return -1;
        }
    }

    printf(
        "Connected clients: %zu/%zu\n",
        client_count,
        client_count
    );

    if (send_test_messages(
            key,
            clients,
            client_count) != 0) {

        fprintf(
            stderr,
            "Failed sending stress messages\n"
        );

        close_clients(
            clients,
            client_count
        );

        free(clients);

        return -1;
    }

    printf(
        "All encrypted messages sent\n"
    );

    if (verify_received_messages(
            key,
            clients,
            client_count) != 0) {

        fprintf(
            stderr,
            "Relay verification FAILED\n"
        );

        close_clients(
            clients,
            client_count
        );

        free(clients);

        return -1;
    }

    printf(
        "All encrypted messages verified\n"
    );

    close_clients(
        clients,
        client_count
    );

    free(clients);

    printf(
        "Result: PASS\n"
    );

    return 0;
}

int main(void)
{
    unsigned char key[
        CRYPTO_KEY_SIZE
    ];

    printf(
        "\n"
        "====================================\n"
        " Secure Relay Stress Test Suite\n"
        "====================================\n"
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

    size_t test_sizes[] = {
        TEST_CLIENTS_10,
        TEST_CLIENTS_50,
        TEST_CLIENTS_100
    };

    size_t test_count =
        sizeof(test_sizes) /
        sizeof(test_sizes[0]);

    for (size_t i = 0;
         i < test_count;
         i++) {

        if (run_stress_test(
                key,
                test_sizes[i]
            ) != 0) {

            printf(
                "\n"
                "====================================\n"
                " STRESS TEST SUITE FAILED\n"
                "====================================\n"
            );

            return EXIT_FAILURE;
        }
    }

    printf(
        "\n"
        "====================================\n"
        " STRESS TEST SUITE PASSED\n"
        "====================================\n"
        "10 clients:  PASS\n"
        "50 clients:  PASS\n"
        "100 clients: PASS\n"
        "====================================\n"
    );

    return EXIT_SUCCESS;
}
