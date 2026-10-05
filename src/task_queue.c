#include "task_queue.h"

#include <string.h>

int task_queue_init(
    task_queue_t *queue
)
{
    if (queue == NULL) {
        return -1;
    }

    memset(
        queue,
        0,
        sizeof(*queue)
    );

    if (pthread_mutex_init(
            &queue->mutex,
            NULL) != 0) {

        return -1;
    }

    if (pthread_cond_init(
            &queue->not_empty,
            NULL) != 0) {

        pthread_mutex_destroy(
            &queue->mutex);

        return -1;
    }

    if (pthread_cond_init(
            &queue->not_full,
            NULL) != 0) {

        pthread_cond_destroy(
            &queue->not_empty);

        pthread_mutex_destroy(
            &queue->mutex);

        return -1;
    }

    return 0;
}

int task_queue_push(
    task_queue_t *queue,
    const task_t *task
)
{
    if (queue == NULL ||
        task == NULL) {

        return -1;
    }

    pthread_mutex_lock(&queue->mutex);

    if (queue->shutdown ||
        queue->count >= TASK_QUEUE_CAPACITY) {

        pthread_mutex_unlock(
            &queue->mutex);

        return -1;
    }

    queue->tasks[queue->tail] = *task;

    queue->tail =
        (queue->tail + 1) %
        TASK_QUEUE_CAPACITY;

    queue->count++;

    pthread_cond_signal(
        &queue->not_empty
    );

    pthread_mutex_unlock(
        &queue->mutex
    );

    return 0;
}

int task_queue_pop(
    task_queue_t *queue,
    task_t *task
)
{
    if (queue == NULL ||
        task == NULL) {

        return -1;
    }

    pthread_mutex_lock(&queue->mutex);

    while (queue->count == 0 &&
           !queue->shutdown) {

        pthread_cond_wait(
            &queue->not_empty,
            &queue->mutex
        );
    }

    if (queue->count == 0 &&
        queue->shutdown) {

        pthread_mutex_unlock(
            &queue->mutex);

        return 1;
    }

    *task =
        queue->tasks[queue->head];

    queue->head =
        (queue->head + 1) %
        TASK_QUEUE_CAPACITY;

    queue->count--;

    pthread_cond_signal(
        &queue->not_full
    );

    pthread_mutex_unlock(
        &queue->mutex
    );

    return 0;
}

void task_queue_shutdown(
    task_queue_t *queue
)
{
    if (queue == NULL) {
        return;
    }

    pthread_mutex_lock(&queue->mutex);

    queue->shutdown = 1;

    pthread_cond_broadcast(
        &queue->not_empty
    );

    pthread_cond_broadcast(
        &queue->not_full
    );

    pthread_mutex_unlock(
        &queue->mutex
    );
}

void task_queue_destroy(
    task_queue_t *queue
)
{
    if (queue == NULL) {
        return;
    }

    pthread_cond_destroy(
        &queue->not_empty);

    pthread_cond_destroy(
        &queue->not_full);

    pthread_mutex_destroy(
        &queue->mutex);
}
