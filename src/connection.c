#include "connection.h"

#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#define FIRST_CLIENT_ID 1U

static pthread_mutex_t registry_mutex =
    PTHREAD_MUTEX_INITIALIZER;

static connection_t *registry_head = NULL;

static uint32_t next_client_id =
    FIRST_CLIENT_ID;


static void destroy_connection(
    connection_t *connection
)
{
    if (connection == NULL) {
        return;
    }

    if (connection->fd >= 0) {
        close(connection->fd);
        connection->fd = -1;
    }

    pthread_cond_destroy(
        &connection->relay_condition
    );

    pthread_mutex_destroy(
        &connection->mutex
    );

    free(connection);
}


connection_t *connection_create(int fd)
{
    connection_t *connection =
        calloc(1, sizeof(connection_t));

    if (connection == NULL) {
        return NULL;
    }

    connection->fd = fd;
    connection->client_id = 0;

    connection->references = 1;
    connection->closed = 0;

    /*
     * Internal worker ordering.
     */
    connection->next_sequence = 0;
    connection->next_relay_sequence = 0;

    /*
     * Protocol replay protection.
     *
     * The first valid message from a client must
     * therefore contain sequence number 0.
     */
    connection->next_incoming_sequence = 1;

    connection->receive_length = 0;

    connection->next = NULL;

    if (pthread_mutex_init(
            &connection->mutex,
            NULL) != 0) {

        free(connection);
        return NULL;
    }

    if (pthread_cond_init(
            &connection->relay_condition,
            NULL) != 0) {

        pthread_mutex_destroy(
            &connection->mutex
        );

        free(connection);
        return NULL;
    }

    return connection;
}


void connection_acquire(
    connection_t *connection
)
{
    if (connection == NULL) {
        return;
    }

    pthread_mutex_lock(
        &connection->mutex
    );

    connection->references++;

    pthread_mutex_unlock(
        &connection->mutex
    );
}


void connection_release(
    connection_t *connection
)
{
    int destroy = 0;

    if (connection == NULL) {
        return;
    }

    pthread_mutex_lock(
        &connection->mutex
    );

    if (connection->references > 0) {

        connection->references--;

        if (connection->references == 0 &&
            connection->closed) {

            destroy = 1;
        }
    }

    pthread_mutex_unlock(
        &connection->mutex
    );

    if (destroy) {
        destroy_connection(connection);
    }
}


void connection_close(
    connection_t *connection
)
{
    if (connection == NULL) {
        return;
    }

    pthread_mutex_lock(
        &connection->mutex
    );

    if (!connection->closed) {

        connection->closed = 1;

        pthread_cond_broadcast(
            &connection->relay_condition
        );

        if (connection->fd >= 0) {

            shutdown(
                connection->fd,
                SHUT_RDWR
            );
        }
    }

    pthread_mutex_unlock(
        &connection->mutex
    );
}


int connection_is_closed(
    connection_t *connection
)
{
    int closed;

    if (connection == NULL) {
        return 1;
    }

    pthread_mutex_lock(
        &connection->mutex
    );

    closed = connection->closed;

    pthread_mutex_unlock(
        &connection->mutex
    );

    return closed;
}


void connection_set_client_id(
    connection_t *connection,
    uint32_t client_id
)
{
    if (connection == NULL) {
        return;
    }

    pthread_mutex_lock(
        &connection->mutex
    );

    connection->client_id = client_id;

    pthread_mutex_unlock(
        &connection->mutex
    );
}


uint32_t connection_get_client_id(
    connection_t *connection
)
{
    uint32_t client_id;

    if (connection == NULL) {
        return 0;
    }

    pthread_mutex_lock(
        &connection->mutex
    );

    client_id = connection->client_id;

    pthread_mutex_unlock(
        &connection->mutex
    );

    return client_id;
}


size_t connection_next_sequence(
    connection_t *connection
)
{
    size_t sequence;

    pthread_mutex_lock(
        &connection->mutex
    );

    sequence = connection->next_sequence++;

    pthread_mutex_unlock(
        &connection->mutex
    );

    return sequence;
}


int connection_wait_for_relay_sequence(
    connection_t *connection,
    size_t sequence
)
{
    int result = 0;

    pthread_mutex_lock(
        &connection->mutex
    );

    while (!connection->closed &&
           connection->next_relay_sequence != sequence) {

        pthread_cond_wait(
            &connection->relay_condition,
            &connection->mutex
        );
    }

    if (!connection->closed &&
        connection->next_relay_sequence == sequence) {

        result = 1;
    }

    pthread_mutex_unlock(
        &connection->mutex
    );

    return result;
}


void connection_complete_relay_sequence(
    connection_t *connection,
    size_t sequence
)
{
    pthread_mutex_lock(
        &connection->mutex
    );

    if (connection->next_relay_sequence == sequence) {

        connection->next_relay_sequence++;

        pthread_cond_broadcast(
            &connection->relay_condition
        );
    }

    pthread_mutex_unlock(
        &connection->mutex
    );
}


/*
 * Replay protection.
 *
 * This function performs the check and increment
 * atomically under the connection mutex.
 *
 * Expected sequence:
 *
 *     0 -> 1 -> 2 -> 3 -> ...
 *
 * If sequence 0 has already been accepted, another
 * sequence 0 is rejected.
 *
 * If sequence 2 arrives while 1 is expected, it is
 * rejected.
 */
int connection_accept_incoming_sequence(
    connection_t *connection,
    uint64_t sequence
)
{
    int accepted = 0;

    if (connection == NULL) {
        return 0;
    }

    pthread_mutex_lock(
        &connection->mutex
    );

    if (!connection->closed &&
        sequence == connection->next_incoming_sequence) {

        connection->next_incoming_sequence++;

        accepted = 1;
    }

    pthread_mutex_unlock(
        &connection->mutex
    );

    return accepted;
}


int connection_registry_add(
    connection_t *connection,
    uint32_t *assigned_id
)
{
    if (connection == NULL ||
        assigned_id == NULL) {

        return -1;
    }

    pthread_mutex_lock(
        &registry_mutex
    );

    /*
     * Zero is reserved for broadcast.
     */
    if (next_client_id == 0) {
        next_client_id = FIRST_CLIENT_ID;
    }

    connection->client_id =
        next_client_id;

    *assigned_id =
        next_client_id;

    next_client_id++;

    connection->next =
        registry_head;

    registry_head =
        connection;

    pthread_mutex_unlock(
        &registry_mutex
    );

    return 0;
}


void connection_registry_remove(
    connection_t *connection
)
{
    connection_t **current;

    if (connection == NULL) {
        return;
    }

    pthread_mutex_lock(
        &registry_mutex
    );

    current = &registry_head;

    while (*current != NULL) {

        if (*current == connection) {

            *current =
                connection->next;

            connection->next = NULL;

            break;
        }

        current =
            &(*current)->next;
    }

    pthread_mutex_unlock(
        &registry_mutex
    );
}


connection_t *connection_registry_find(
    uint32_t client_id
)
{
    connection_t *current;
    connection_t *result = NULL;

    pthread_mutex_lock(
        &registry_mutex
    );

    current = registry_head;

    while (current != NULL) {

        if (current->client_id ==
            client_id) {

            pthread_mutex_lock(
                &current->mutex
            );

            if (!current->closed) {

                current->references++;

                result = current;
            }

            pthread_mutex_unlock(
                &current->mutex
            );

            break;
        }

        current = current->next;
    }

    pthread_mutex_unlock(
        &registry_mutex
    );

    return result;
}


size_t connection_registry_snapshot(
    connection_t **connections,
    size_t max_connections,
    connection_t *exclude
)
{
    size_t count = 0;

    connection_t *current;

    if (connections == NULL ||
        max_connections == 0) {

        return 0;
    }

    pthread_mutex_lock(
        &registry_mutex
    );

    current = registry_head;

    while (current != NULL &&
           count < max_connections) {

        if (current != exclude) {

            pthread_mutex_lock(
                &current->mutex
            );

            if (!current->closed) {

                current->references++;

                connections[count++] =
                    current;
            }

            pthread_mutex_unlock(
                &current->mutex
            );
        }

        current = current->next;
    }

    pthread_mutex_unlock(
        &registry_mutex
    );

    return count;
}


void connection_registry_close_all(void)
{
    connection_t *current;

    pthread_mutex_lock(
        &registry_mutex
    );

    current = registry_head;

    registry_head = NULL;

    while (current != NULL) {

        connection_t *next =
            current->next;

        current->next = NULL;

        connection_close(
            current
        );

        /*
         * Release server/registry ownership.
         * Worker references keep queued tasks
         * alive.
         */
        connection_release(
            current
        );

        current = next;
    }

    pthread_mutex_unlock(
        &registry_mutex
    );
}
