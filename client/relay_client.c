#include "crypto.h"
#include "key_manager.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SERVER_PORT 9090
#define INPUT_SIZE 4096

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

        if (result > 0) {
            received += (size_t)result;
            continue;
        }

        if (result < 0 &&
            errno == EINTR) {
            continue;
        }

        return -1;
    }

    return 0;
}

static int receive_frame(
    int fd,
    unsigned char *frame,
    size_t capacity,
    size_t *frame_length
)
{
    if (capacity <
        PROTOCOL_HEADER_SIZE) {

        return -1;
    }

    if (recv_all(
            fd,
            frame,
            PROTOCOL_HEADER_SIZE
        ) != 0) {

        return -1;
    }

    uint32_t ciphertext_length =
        ((uint32_t)frame[18] << 24) |
        ((uint32_t)frame[19] << 16) |
        ((uint32_t)frame[20] << 8) |
        (uint32_t)frame[21];

    size_t total_length =
        PROTOCOL_HEADER_SIZE +
        ciphertext_length;

    if (total_length > capacity ||
        total_length >
            PROTOCOL_MAX_FRAME_SIZE) {

        return -1;
    }

    if (ciphertext_length > 0) {

        if (recv_all(
                fd,
                frame +
                    PROTOCOL_HEADER_SIZE,
                ciphertext_length
            ) != 0) {

            return -1;
        }
    }

    *frame_length =
        total_length;

    return 0;
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
                MSG_NOSIGNAL
            );

        if (result > 0) {
            sent += (size_t)result;
            continue;
        }

        if (result < 0 &&
            errno == EINTR) {
            continue;
        }

        return -1;
    }

    return 0;
}

typedef struct {
    int fd;

    uint32_t client_id;

    unsigned char key[
        CRYPTO_KEY_SIZE
    ];

    volatile int running;

    pthread_mutex_t print_mutex;

} client_context_t;

static void *receiver_thread(
    void *argument
)
{
    client_context_t *context =
        argument;

    unsigned char frame[
        PROTOCOL_MAX_FRAME_SIZE
    ];

    while (context->running) {

        size_t frame_length = 0;

        if (receive_frame(
                context->fd,
                frame,
                sizeof(frame),
                &frame_length
            ) != 0) {

            break;
        }

        protocol_frame_info info;

        if (protocol_parse_frame(
                frame,
                frame_length,
                &info
            ) != 0) {

            fprintf(
                stderr,
                "\nReceiver: invalid frame\n"
            );

            break;
        }

        if (info.type ==
            PROTOCOL_TYPE_CLIENT_ID) {

            continue;
        }

        if (info.type !=
            PROTOCOL_TYPE_MESSAGE) {

            continue;
        }

        unsigned char plaintext[
            PROTOCOL_MAX_PAYLOAD
        ];

        size_t plaintext_length = 0;

        if (protocol_decrypt_message(
                context->key,
                frame,
                frame_length,
                plaintext,
                sizeof(plaintext),
                &plaintext_length
            ) != 0) {

            fprintf(
                stderr,
                "\nReceiver: authentication "
                "failed\n> "
            );

            fflush(stdout);
            continue;
        }

        pthread_mutex_lock(
            &context->print_mutex
        );

        printf(
            "\n[Client %u] ",
            info.sender_id
        );

        fwrite(
            plaintext,
            1,
            plaintext_length,
            stdout
        );

        printf("\n> ");
        fflush(stdout);

        pthread_mutex_unlock(
            &context->print_mutex
        );
    }

    context->running = 0;

    return NULL;
}

int main(
    int argc,
    char **argv
)
{
    if (argc != 2) {

        fprintf(
            stderr,
            "Usage: %s <server-ip>\n",
            argv[0]
        );

        return EXIT_FAILURE;
    }

    signal(
        SIGPIPE,
        SIG_IGN
    );

    if (crypto_init() != 0) {

        fprintf(
            stderr,
            "crypto_init failed\n"
        );

        return EXIT_FAILURE;
    }

    unsigned char key[
        CRYPTO_KEY_SIZE
    ];

    if (key_load(
            "config/shared.key",
            key
        ) != 0) {

        fprintf(
            stderr,
            "Unable to load config/shared.key\n"
        );

        return EXIT_FAILURE;
    }

    int fd =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );

    if (fd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    struct sockaddr_in server;

    memset(
        &server,
        0,
        sizeof(server)
    );

    server.sin_family =
        AF_INET;

    server.sin_port =
        htons(SERVER_PORT);

    if (inet_pton(
            AF_INET,
            argv[1],
            &server.sin_addr
        ) != 1) {

        fprintf(
            stderr,
            "Invalid server IP\n"
        );

        close(fd);
        return EXIT_FAILURE;
    }

    if (connect(
            fd,
            (struct sockaddr *)&server,
            sizeof(server)
        ) != 0) {

        perror("connect");
        close(fd);
        return EXIT_FAILURE;
    }

    unsigned char frame[
        PROTOCOL_MAX_FRAME_SIZE
    ];

    size_t frame_length = 0;

    if (receive_frame(
            fd,
            frame,
            sizeof(frame),
            &frame_length
        ) != 0) {

        fprintf(
            stderr,
            "Failed receiving client ID\n"
        );

        close(fd);
        return EXIT_FAILURE;
    }

    protocol_frame_info id_info;

    if (protocol_parse_frame(
            frame,
            frame_length,
            &id_info
        ) != 0 ||
        id_info.type !=
            PROTOCOL_TYPE_CLIENT_ID) {

        fprintf(
            stderr,
            "Invalid client ID frame\n"
        );

        close(fd);
        return EXIT_FAILURE;
    }

    client_context_t context;

    memset(
        &context,
        0,
        sizeof(context)
    );

    context.fd = fd;
    context.client_id =
        id_info.target_id;

    memcpy(
        context.key,
        key,
        CRYPTO_KEY_SIZE
    );

    context.running = 1;

    pthread_mutex_init(
        &context.print_mutex,
        NULL
    );

    printf(
        "\nConnected to Secure Multi-Client Relay\n"
    );

    printf(
        "Your client ID: %u\n\n",
        context.client_id
    );

    printf(
        "/all <message>       Broadcast\n"
        "/to <id> <message>   Direct message\n"
        "/quit                Exit\n\n"
    );

    pthread_t receiver;

    if (pthread_create(
            &receiver,
            NULL,
            receiver_thread,
            &context
        ) != 0) {

        fprintf(
            stderr,
            "Failed to create receiver thread\n"
        );

        close(fd);

        pthread_mutex_destroy(
            &context.print_mutex
        );

        return EXIT_FAILURE;
    }

    uint64_t sequence = 1;

    char input[
        INPUT_SIZE
    ];

    while (context.running) {

        printf("> ");
        fflush(stdout);

        if (fgets(
                input,
                sizeof(input),
                stdin
            ) == NULL) {

            break;
        }

        size_t input_length =
            strlen(input);

        while (input_length > 0 &&
               (input[input_length - 1] ==
                    '\n' ||
                input[input_length - 1] ==
                    '\r')) {

            input[--input_length] =
                '\0';
        }

        if (strcmp(
                input,
                "/quit"
            ) == 0) {

            break;
        }

        uint32_t target_id = 0;

        const char *message = NULL;

        if (strncmp(
                input,
                "/all ",
                5
            ) == 0) {

            target_id = 0;
            message = input + 5;

        } else if (
            strncmp(
                input,
                "/to ",
                4
            ) == 0) {

            char *end = NULL;

            unsigned long id =
                strtoul(
                    input + 4,
                    &end,
                    10
                );

            if (end == input + 4 ||
                *end != ' ') {

                printf(
                    "Usage: /to <id> <message>\n"
                );

                continue;
            }

            if (id == 0 ||
                id > UINT32_MAX) {

                printf(
                    "Invalid client ID\n"
                );

                continue;
            }

            target_id =
                (uint32_t)id;

            message =
                end + 1;

        } else {

            printf(
                "Use /all <message> or "
                "/to <id> <message>\n"
            );

            continue;
        }

        size_t message_length =
            strlen(message);

        if (message_length == 0) {
            continue;
        }

        unsigned char encrypted_frame[
            PROTOCOL_MAX_FRAME_SIZE
        ];

        size_t encrypted_length = 0;

        if (protocol_build_message_frame(
                context.key,
                context.client_id,
                target_id,
                sequence++,
                (const unsigned char *)message,
                message_length,
                encrypted_frame,
                sizeof(encrypted_frame),
                &encrypted_length
            ) != 0) {

            fprintf(
                stderr,
                "Encryption failed\n"
            );

            continue;
        }

        if (send_all(
                fd,
                encrypted_frame,
                encrypted_length
            ) != 0) {

            perror("send");
            break;
        }
    }

    context.running = 0;

    shutdown(
        fd,
        SHUT_RDWR
    );

    pthread_join(
        receiver,
        NULL
    );

    close(fd);

    pthread_mutex_destroy(
        &context.print_mutex
    );

    printf(
        "Disconnected\n"
    );

    return EXIT_SUCCESS;
}
