#ifndef CONNECTION_H
#define CONNECTION_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#define CONNECTION_BUFFER_SIZE 8192

typedef struct connection {
    int fd;

    uint32_t client_id;

    pthread_mutex_t mutex;
    pthread_cond_t relay_condition;

    size_t references;

    int closed;

    /*
     * Sequence numbers assigned internally by the
     * epoll thread for worker ordering.
     */
    size_t next_sequence;

    /*
     * Worker-side sequence ordering.
     */
    size_t next_relay_sequence;

    /*
     * Protocol sequence number expected from this
     * client.
     *
     * Each client must send:
     *
     *     1, 2, 3, 4, ...
     *
     * A duplicate or out-of-order sequence is
     * rejected as a replay/protocol violation.
     */
    uint64_t next_incoming_sequence;

    /*
     * TCP receive buffer.
     */
    unsigned char receive_buffer[CONNECTION_BUFFER_SIZE];
    size_t receive_length;

    /*
     * Active connection registry linkage.
     */
    struct connection *next;

} connection_t;


/* Lifetime management */

connection_t *connection_create(int fd);

void connection_acquire(connection_t *connection);

void connection_release(connection_t *connection);

void connection_close(connection_t *connection);

int connection_is_closed(connection_t *connection);


/* Client identity */

void connection_set_client_id(
    connection_t *connection,
    uint32_t client_id
);

uint32_t connection_get_client_id(
    connection_t *connection
);


/* Per-client sequencing */

size_t connection_next_sequence(
    connection_t *connection
);

int connection_wait_for_relay_sequence(
    connection_t *connection,
    size_t sequence
);

void connection_complete_relay_sequence(
    connection_t *connection,
    size_t sequence
);


/*
 * Replay protection.
 *
 * Accepts exactly the next expected protocol
 * sequence number.
 *
 * The first valid application message uses
 * sequence number 1.
 *
 * Returns:
 *     1 = accepted
 *     0 = replay/out-of-order/closed
 */
int connection_accept_incoming_sequence(
    connection_t *connection,
    uint64_t sequence
);


/* Active connection registry */

int connection_registry_add(
    connection_t *connection,
    uint32_t *assigned_id
);

void connection_registry_remove(
    connection_t *connection
);

connection_t *connection_registry_find(
    uint32_t client_id
);

size_t connection_registry_snapshot(
    connection_t **connections,
    size_t capacity,
    connection_t *exclude
);

void connection_registry_close_all(void);

#endif
