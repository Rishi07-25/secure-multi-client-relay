#include "frame_io.h"

#include "protocol.h"

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int fill_receive_buffer(
    connection_t *connection
)
{
    for (;;) {

        if (connection->receive_length >=
            sizeof(connection->receive_buffer)) {

            return FRAME_IO_ERROR;
        }

        ssize_t received = recv(
            connection->fd,
            connection->receive_buffer +
                connection->receive_length,
            sizeof(connection->receive_buffer) -
                connection->receive_length,
            0
        );

        if (received > 0) {

            connection->receive_length +=
                (size_t)received;

            continue;
        }

        if (received == 0) {
            return FRAME_IO_CLOSED;
        }

        if (errno == EINTR) {
            continue;
        }

        if (errno == EAGAIN ||
            errno == EWOULDBLOCK) {

            return FRAME_IO_INCOMPLETE;
        }

        return FRAME_IO_ERROR;
    }
}

int recv_protocol_frame(
    connection_t *connection,
    unsigned char *frame,
    size_t frame_capacity,
    size_t *frame_length
)
{
    size_t required_length;
    uint32_t ciphertext_length;

    if (connection == NULL ||
        frame == NULL ||
        frame_length == NULL) {

        return FRAME_IO_ERROR;
    }

    for (;;) {

        if (connection->receive_length <
            PROTOCOL_HEADER_SIZE) {

            int result =
                fill_receive_buffer(
                    connection
                );

            if (result ==
                FRAME_IO_CLOSED) {

                return FRAME_IO_CLOSED;
            }

            if (result ==
                FRAME_IO_ERROR) {

                return FRAME_IO_ERROR;
            }

            if (connection->receive_length <
                PROTOCOL_HEADER_SIZE) {

                return FRAME_IO_INCOMPLETE;
            }
        }

        if (connection->receive_buffer[0] !=
            PROTOCOL_VERSION) {

            return FRAME_IO_ERROR;
        }

        ciphertext_length =
            ((uint32_t)
                connection->receive_buffer[18] << 24) |
            ((uint32_t)
                connection->receive_buffer[19] << 16) |
            ((uint32_t)
                connection->receive_buffer[20] << 8) |
            ((uint32_t)
                connection->receive_buffer[21]);

        if (ciphertext_length >
            PROTOCOL_MAX_PAYLOAD +
            CRYPTO_MAC_SIZE) {

            return FRAME_IO_ERROR;
        }

        required_length =
            PROTOCOL_HEADER_SIZE +
            ciphertext_length;

        if (required_length >
            frame_capacity) {

            return FRAME_IO_ERROR;
        }

        if (required_length >
            sizeof(connection->receive_buffer)) {

            return FRAME_IO_ERROR;
        }

        if (connection->receive_length <
            required_length) {

            int result =
                fill_receive_buffer(
                    connection
                );

            if (result ==
                FRAME_IO_CLOSED) {

                return FRAME_IO_CLOSED;
            }

            if (result ==
                FRAME_IO_ERROR) {

                return FRAME_IO_ERROR;
            }

            if (connection->receive_length <
                required_length) {

                return FRAME_IO_INCOMPLETE;
            }
        }

        memcpy(
            frame,
            connection->receive_buffer,
            required_length
        );

        connection->receive_length -=
            required_length;

        if (connection->receive_length > 0) {

            memmove(
                connection->receive_buffer,
                connection->receive_buffer +
                    required_length,
                connection->receive_length
            );
        }

        *frame_length =
            required_length;

        return FRAME_IO_COMPLETE;
    }
}

int send_all_bytes(
    int fd,
    const unsigned char *data,
    size_t length
)
{
    size_t sent_total = 0;

    while (sent_total < length) {

        ssize_t sent = send(
            fd,
            data + sent_total,
            length - sent_total,
            MSG_NOSIGNAL
        );

        if (sent > 0) {
            sent_total += (size_t)sent;
            continue;
        }

        if (sent < 0 &&
            errno == EINTR) {

            continue;
        }

        if (sent < 0 &&
            (errno == EAGAIN ||
             errno == EWOULDBLOCK)) {

            struct pollfd poll_fd;

            poll_fd.fd = fd;
            poll_fd.events = POLLOUT;
            poll_fd.revents = 0;

            int result = poll(
                &poll_fd,
                1,
                1000
            );

            if (result > 0) {
                continue;
            }

            return -1;
        }

        return -1;
    }

    return 0;
}
