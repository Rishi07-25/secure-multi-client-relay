#include "connection.h"
#include "frame_io.h"
#include "protocol.h"
#include "task_queue.h"
#include "worker_pool.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#define SERVER_PORT 9090
#define BACKLOG 32
#define MAX_EVENTS 64

static volatile sig_atomic_t stop_requested = 0;


static void handle_sigint(
    int signal_number
)
{
    (void)signal_number;

    stop_requested = 1;
}


static void die(
    const char *message
)
{
    perror(message);
    exit(EXIT_FAILURE);
}


static int set_nonblocking(
    int fd
)
{
    int flags =
        fcntl(fd, F_GETFL, 0);

    if (flags < 0) {
        return -1;
    }

    if (fcntl(
            fd,
            F_SETFL,
            flags | O_NONBLOCK) < 0) {

        return -1;
    }

    return 0;
}


static void remove_connection_from_epoll(
    int epoll_fd,
    connection_t *connection
)
{
    if (epoll_ctl(
            epoll_fd,
            EPOLL_CTL_DEL,
            connection->fd,
            NULL) < 0) {

        if (errno != ENOENT &&
            errno != EBADF) {

            perror(
                "epoll_ctl DEL"
            );
        }
    }
}


static int add_connection_to_epoll(
    int epoll_fd,
    connection_t *connection
)
{
    struct epoll_event event;

    memset(
        &event,
        0,
        sizeof(event)
    );

    event.events =
        EPOLLIN |
        EPOLLRDHUP;

    event.data.ptr =
        connection;

    return epoll_ctl(
        epoll_fd,
        EPOLL_CTL_ADD,
        connection->fd,
        &event
    );
}


static void close_connection(
    int epoll_fd,
    connection_t *connection
)
{
    if (connection == NULL) {
        return;
    }

    remove_connection_from_epoll(
        epoll_fd,
        connection
    );

    connection_registry_remove(
        connection
    );

    connection_close(
        connection
    );

    /*
     * Release server ownership.
     *
     * Queued workers still have their own
     * references.
     */
    connection_release(
        connection
    );
}


static int send_client_id(
    connection_t *connection
)
{
    unsigned char frame[
        PROTOCOL_HEADER_SIZE
    ];

    size_t frame_length = 0;

    if (protocol_build_client_id_frame(
            connection_get_client_id(
                connection
            ),
            frame,
            sizeof(frame),
            &frame_length) != 0) {

        return -1;
    }

    return send_all_bytes(
        connection->fd,
        frame,
        frame_length
    );
}


static int handle_client_data(
    int epoll_fd,
    task_queue_t *task_queue,
    connection_t *connection
)
{
    unsigned char frame[
        PROTOCOL_MAX_FRAME_SIZE
    ];

    for (;;) {

        size_t frame_length = 0;

        int result =
            recv_protocol_frame(
                connection,
                frame,
                sizeof(frame),
                &frame_length
            );

        if (result ==
            FRAME_IO_INCOMPLETE) {

            return 0;
        }

        if (result ==
            FRAME_IO_CLOSED) {

            printf(
                "Client disconnected: "
                "id=%u fd=%d\n",
                connection_get_client_id(
                    connection
                ),
                connection->fd
            );

            close_connection(
                epoll_fd,
                connection
            );

            return 1;
        }

        if (result ==
            FRAME_IO_ERROR) {

            fprintf(
                stderr,
                "Invalid frame from "
                "client id=%u fd=%d\n",
                connection_get_client_id(
                    connection
                ),
                connection->fd
            );

            close_connection(
                epoll_fd,
                connection
            );

            return 1;
        }

        protocol_frame_info info;

        if (protocol_parse_frame(
                frame,
                frame_length,
                &info) != 0) {

            fprintf(
                stderr,
                "Protocol validation failed "
                "for client id=%u\n",
                connection_get_client_id(
                    connection
                )
            );

            close_connection(
                epoll_fd,
                connection
            );

            return 1;
        }

        /*
         * Clients are not allowed to send
         * server-control frames.
         */
        if (info.type !=
            PROTOCOL_TYPE_MESSAGE) {

            fprintf(
                stderr,
                "Client id=%u sent invalid "
                "control frame\n",
                connection_get_client_id(
                    connection
                )
            );

            close_connection(
                epoll_fd,
                connection
            );

            return 1;
        }

        /*
         * Validate the sender identity.
         *
         * A client may only submit frames claiming
         * to originate from its own assigned ID.
         */
        if (info.sender_id !=
            connection_get_client_id(
                connection
            )) {

            fprintf(
                stderr,
                "Sender ID mismatch: "
                "connection=%u frame=%u\n",
                connection_get_client_id(
                    connection
                ),
                info.sender_id
            );

            close_connection(
                epoll_fd,
                connection
            );

            return 1;
        }

        /*
         * Replay protection.
         *
         * Every client must send protocol sequence
         * numbers in strict order:
         *
         *     0, 1, 2, 3, ...
         *
         * A previously accepted frame therefore
         * cannot be submitted again.
         *
         * This check happens before the frame enters
         * the worker queue.
         */
        if (!connection_accept_incoming_sequence(
                connection,
                info.sequence
            )) {

            fprintf(
                stderr,
                "Replay/out-of-order frame: "
                "client=%u sequence=%llu\n",
                connection_get_client_id(
                    connection
                ),
                (unsigned long long)
                    info.sequence
            );

            close_connection(
                epoll_fd,
                connection
            );

            return 1;
        }

        /*
         * Acquire a worker reference.
         */
        connection_acquire(
            connection
        );

        task_t task;

        memset(
            &task,
            0,
            sizeof(task)
        );

        task.connection =
            connection;

        /*
         * Internal worker ordering sequence.
         */
        task.sequence =
            connection_next_sequence(
                connection
            );

        task.data_length =
            frame_length;

        memcpy(
            task.data,
            frame,
            frame_length
        );

        if (task_queue_push(
                task_queue,
                &task
            ) != 0) {

            fprintf(
                stderr,
                "Task queue full; "
                "closing client id=%u fd=%d\n",
                connection_get_client_id(
                    connection
                ),
                connection->fd
            );

            /*
             * Task never entered the queue,
             * so release its reference.
             */
            connection_release(
                connection
            );

            close_connection(
                epoll_fd,
                connection
            );

            return 1;
        }

        printf(
            "Encrypted frame queued: "
            "client=%u target=%u bytes=%zu\n",
            info.sender_id,
            info.target_id,
            frame_length
        );
    }
}


int main(void)
{
    int server_fd;
    int epoll_fd;

    int reuse_address = 1;

    struct sockaddr_in server_address;

    struct epoll_event server_event;

    struct epoll_event events[
        MAX_EVENTS
    ];

    task_queue_t task_queue;

    worker_pool_t worker_pool;

    signal(
        SIGPIPE,
        SIG_IGN
    );

    signal(
        SIGINT,
        handle_sigint
    );

    /*
     * Create listening socket.
     */
    server_fd = socket(
        AF_INET,
        SOCK_STREAM,
        0
    );

    if (server_fd < 0) {
        die("socket");
    }

    if (setsockopt(
            server_fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            &reuse_address,
            sizeof(reuse_address)) < 0) {

        die("setsockopt");
    }

    if (set_nonblocking(
            server_fd) != 0) {

        die("set_nonblocking");
    }

    memset(
        &server_address,
        0,
        sizeof(server_address)
    );

    server_address.sin_family =
        AF_INET;

    server_address.sin_addr.s_addr =
        htonl(INADDR_ANY);

    server_address.sin_port =
        htons(SERVER_PORT);

    if (bind(
            server_fd,
            (struct sockaddr *)&server_address,
            sizeof(server_address)) < 0) {

        die("bind");
    }

    if (listen(
            server_fd,
            BACKLOG) < 0) {

        die("listen");
    }

    /*
     * epoll.
     */
    epoll_fd =
        epoll_create1(0);

    if (epoll_fd < 0) {
        die("epoll_create1");
    }

    memset(
        &server_event,
        0,
        sizeof(server_event)
    );

    server_event.events =
        EPOLLIN;

    /*
     * NULL means listening socket.
     */
    server_event.data.ptr = NULL;

    if (epoll_ctl(
            epoll_fd,
            EPOLL_CTL_ADD,
            server_fd,
            &server_event) < 0) {

        die(
            "epoll_ctl ADD server"
        );
    }

    /*
     * Queue.
     */
    if (task_queue_init(
            &task_queue) != 0) {

        die("task_queue_init");
    }

    /*
     * Worker pool.
     */
    if (worker_pool_init(
            &worker_pool,
            &task_queue) != 0) {

        die("worker_pool_init");
    }

    printf(
        "Secure multi-client relay server\n"
    );

    printf(
        "Listening on port %d\n",
        SERVER_PORT
    );

    printf(
        "Worker pool started with %d workers\n",
        WORKER_COUNT
    );

    printf(
        "Mode: blind encrypted relay\n"
    );

    while (!stop_requested) {

        int event_count =
            epoll_wait(
                epoll_fd,
                events,
                MAX_EVENTS,
                -1
            );

        if (event_count < 0) {

            if (errno == EINTR) {
                continue;
            }

            die("epoll_wait");
        }

        for (int i = 0;
             i < event_count;
             i++) {

            /*
             * Listening socket.
             */
            if (events[i].data.ptr == NULL) {

                for (;;) {

                    struct sockaddr_in
                        client_address;

                    socklen_t client_length =
                        sizeof(client_address);

                    int client_fd =
                        accept(
                            server_fd,
                            (struct sockaddr *)
                                &client_address,
                            &client_length
                        );

                    if (client_fd < 0) {

                        if (errno == EAGAIN ||
                            errno == EWOULDBLOCK) {

                            break;
                        }

                        if (errno == EINTR) {
                            continue;
                        }

                        perror("accept");
                        break;
                    }

                    if (set_nonblocking(
                            client_fd) != 0) {

                        perror(
                            "client nonblocking"
                        );

                        close(client_fd);
                        continue;
                    }

                    connection_t *connection =
                        connection_create(
                            client_fd
                        );

                    if (connection == NULL) {

                        fprintf(
                            stderr,
                            "Failed to create "
                            "connection object\n"
                        );

                        close(client_fd);
                        continue;
                    }

                    uint32_t client_id = 0;

                    if (connection_registry_add(
                            connection,
                            &client_id
                        ) != 0) {

                        fprintf(
                            stderr,
                            "Failed to register "
                            "client\n"
                        );

                        connection_close(
                            connection
                        );

                        connection_release(
                            connection
                        );

                        continue;
                    }

                    if (add_connection_to_epoll(
                            epoll_fd,
                            connection
                        ) != 0) {

                        perror(
                            "epoll_ctl ADD client"
                        );

                        connection_registry_remove(
                            connection
                        );

                        connection_close(
                            connection
                        );

                        connection_release(
                            connection
                        );

                        continue;
                    }

                    char client_ip[
                        INET_ADDRSTRLEN
                    ];

                    if (inet_ntop(
                            AF_INET,
                            &client_address.sin_addr,
                            client_ip,
                            sizeof(client_ip)
                        ) == NULL) {

                        strcpy(
                            client_ip,
                            "unknown"
                        );
                    }

                    printf(
                        "Client connected: "
                        "id=%u %s:%d fd=%d\n",
                        client_id,
                        client_ip,
                        ntohs(
                            client_address.sin_port
                        ),
                        client_fd
                    );

                    /*
                     * Tell the client its assigned ID.
                     */
                    if (send_client_id(
                            connection
                        ) != 0) {

                        fprintf(
                            stderr,
                            "Failed sending client ID "
                            "to id=%u\n",
                            client_id
                        );

                        close_connection(
                            epoll_fd,
                            connection
                        );

                        continue;
                    }
                }

                continue;
            }

            connection_t *connection =
                events[i].data.ptr;

            if (connection == NULL) {
                continue;
            }

            /*
             * EPOLLHUP/RDHUP/ERR means the connection
             * needs to be closed.
             */
            if (events[i].events &
                (EPOLLERR |
                 EPOLLHUP |
                 EPOLLRDHUP)) {

                if (events[i].events &
                    EPOLLIN) {

                    if (handle_client_data(
                            epoll_fd,
                            &task_queue,
                            connection
                        ) == 1) {

                        continue;
                    }
                }

                if (!connection_is_closed(
                        connection)) {

                    printf(
                        "Client disconnected: "
                        "id=%u fd=%d\n",
                        connection_get_client_id(
                            connection
                        ),
                        connection->fd
                    );

                    close_connection(
                        epoll_fd,
                        connection
                    );
                }

                continue;
            }

            if (events[i].events &
                EPOLLIN) {

                handle_client_data(
                    epoll_fd,
                    &task_queue,
                    connection
                );
            }
        }
    }

    printf(
        "Shutdown requested\n"
    );

    /*
     * Stop accepting new clients first.
     */
    epoll_ctl(
        epoll_fd,
        EPOLL_CTL_DEL,
        server_fd,
        NULL
    );

    /*
     * Close all active clients.
     *
     * Worker references keep queued tasks alive.
     */
    connection_registry_close_all();

    close(server_fd);
    close(epoll_fd);

    /*
     * Drain queued tasks and stop workers.
     */
    worker_pool_destroy(
        &worker_pool
    );

    task_queue_destroy(
        &task_queue
    );

    printf(
        "Relay server shutdown complete\n"
    );

    return 0;
}
