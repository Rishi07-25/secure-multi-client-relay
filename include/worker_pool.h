#ifndef WORKER_POOL_H
#define WORKER_POOL_H

#include "task_queue.h"

#include <pthread.h>

#define WORKER_COUNT 4

typedef struct {
    pthread_t workers[WORKER_COUNT];

    task_queue_t *queue;

    int started;

} worker_pool_t;

int worker_pool_init(
    worker_pool_t *pool,
    task_queue_t *queue
);

void worker_pool_destroy(
    worker_pool_t *pool
);

#endif
