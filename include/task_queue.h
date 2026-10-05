#ifndef TASK_QUEUE_H
#define TASK_QUEUE_H

#include "connection.h"
#include "protocol.h"

#include <pthread.h>
#include <stddef.h>

#define TASK_QUEUE_CAPACITY 64

typedef struct {
    connection_t *connection;

    size_t sequence;

    size_t data_length;

    unsigned char data[
        PROTOCOL_MAX_FRAME_SIZE
    ];

} task_t;

typedef struct {
    task_t tasks[TASK_QUEUE_CAPACITY];

    size_t head;
    size_t tail;
    size_t count;

    int shutdown;

    pthread_mutex_t mutex;

    pthread_cond_t not_empty;
    pthread_cond_t not_full;

} task_queue_t;

int task_queue_init(
    task_queue_t *queue
);

int task_queue_push(
    task_queue_t *queue,
    const task_t *task
);

int task_queue_pop(
    task_queue_t *queue,
    task_t *task
);

void task_queue_shutdown(
    task_queue_t *queue
);

void task_queue_destroy(
    task_queue_t *queue
);

#endif
