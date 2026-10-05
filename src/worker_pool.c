#include "worker_pool.h"

#include "connection.h"
#include "frame_io.h"
#include "protocol.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_RELAY_TARGETS 128


static int relay_to_target(
    connection_t *target,
    const unsigned char *frame,
    size_t frame_length
)
{
    if (target == NULL) {
        return -1;
    }

    if (connection_is_closed(target)) {
        return -1;
    }

    if (send_all_bytes(
            target->fd,
            frame,
            frame_length) != 0) {

        connection_close(target);

        return -1;
    }

    return 0;
}


static void process_task(
    const task_t *task
)
{
    connection_t *source;
    protocol_frame_info info;

    if (task == NULL ||
        task->connection == NULL) {

        return;
    }

    source = task->connection;

    /*
     * Preserve the order in which a single client
     * submitted messages.
     */
    if (!connection_wait_for_relay_sequence(
            source,
            task->sequence)) {

        return;
    }

    if (connection_is_closed(source)) {

        connection_complete_relay_sequence(
            source,
            task->sequence
        );

        return;
    }

    /*
     * The server ONLY parses routing metadata.
     *
     * It deliberately does not call
     * protocol_decrypt_message().
     */
    if (protocol_parse_frame(
            task->data,
            task->data_length,
            &info) != 0) {

        fprintf(
            stderr,
            "Worker: invalid relay frame from client %u\n",
            connection_get_client_id(source)
        );

        connection_close(source);

        connection_complete_relay_sequence(
            source,
            task->sequence
        );

        return;
    }

    if (info.type !=
        PROTOCOL_TYPE_MESSAGE) {

        fprintf(
            stderr,
            "Worker: unexpected control frame from client %u\n",
            connection_get_client_id(source)
        );

        connection_close(source);

        connection_complete_relay_sequence(
            source,
            task->sequence
        );

        return;
    }

    /*
     * Prevent a client from pretending to be another
     * client by changing sender_id.
     */
    if (info.sender_id !=
        connection_get_client_id(source)) {

        fprintf(
            stderr,
            "Worker: sender ID mismatch "
            "client=%u claimed=%u\n",
            connection_get_client_id(source),
            info.sender_id
        );

        connection_close(source);

        connection_complete_relay_sequence(
            source,
            task->sequence
        );

        return;
    }

    /*
     * Replay protection.
     *
     * The protocol sequence number is authenticated
     * as part of the frame AAD, so a client cannot
     * safely modify it without invalidating the
     * encrypted message.
     *
     * Every client must submit:
     *
     *     0, 1, 2, 3, ...
     *
     * A duplicate or skipped sequence is rejected.
     */

    /*
     * Broadcast.
     */
    if (info.target_id ==
        PROTOCOL_BROADCAST_ID) {

        connection_t *targets[
            MAX_RELAY_TARGETS
        ];

        size_t target_count =
            connection_registry_snapshot(
                targets,
                MAX_RELAY_TARGETS,
                source
            );

        printf(
            "Relay: client %u broadcasting "
            "%zu-byte encrypted frame to %zu clients\n",
            info.sender_id,
            task->data_length,
            target_count
        );

        for (size_t i = 0;
             i < target_count;
             i++) {

            if (relay_to_target(
                    targets[i],
                    task->data,
                    task->data_length) != 0) {

                fprintf(
                    stderr,
                    "Relay: failed sending "
                    "to client %u\n",
                    connection_get_client_id(
                        targets[i]
                    )
                );
            }

            connection_release(
                targets[i]
            );
        }

    } else {

        /*
         * Direct message.
         */
        connection_t *target =
            connection_registry_find(
                info.target_id
            );

        if (target == NULL) {

            printf(
                "Relay: target client %u "
                "is not connected\n",
                info.target_id
            );

        } else {

            printf(
                "Relay: client %u -> client %u "
                "(%zu encrypted bytes)\n",
                info.sender_id,
                info.target_id,
                task->data_length
            );

            if (relay_to_target(
                    target,
                    task->data,
                    task->data_length) != 0) {

                fprintf(
                    stderr,
                    "Relay: failed sending "
                    "to client %u\n",
                    info.target_id
                );
            }

            connection_release(target);
        }
    }

    connection_complete_relay_sequence(
        source,
        task->sequence
    );
}


static void *worker_main(
    void *argument
)
{
    worker_pool_t *pool =
        argument;

    for (;;) {

        task_t task;

        int result =
            task_queue_pop(
                pool->queue,
                &task
            );

        if (result == 1) {
            break;
        }

        if (result != 0) {
            continue;
        }

        process_task(&task);

        /*
         * Release the worker's task reference.
         */
        connection_release(
            task.connection
        );
    }

    return NULL;
}


int worker_pool_init(
    worker_pool_t *pool,
    task_queue_t *queue
)
{
    if (pool == NULL ||
        queue == NULL) {

        return -1;
    }

    pool->queue = queue;
    pool->started = 0;

    for (int i = 0;
         i < WORKER_COUNT;
         i++) {

        if (pthread_create(
                &pool->workers[i],
                NULL,
                worker_main,
                pool) != 0) {

            task_queue_shutdown(queue);

            for (int j = 0;
                 j < i;
                 j++) {

                pthread_join(
                    pool->workers[j],
                    NULL
                );
            }

            return -1;
        }

        pool->started++;
    }

    return 0;
}


void worker_pool_destroy(
    worker_pool_t *pool
)
{
    if (pool == NULL) {
        return;
    }

    task_queue_shutdown(
        pool->queue
    );

    for (int i = 0;
         i < pool->started;
         i++) {

        pthread_join(
            pool->workers[i],
            NULL
        );
    }

    pool->started = 0;
}
