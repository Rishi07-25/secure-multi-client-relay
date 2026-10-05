#include "task_queue.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#define TEST_TASKS 10

static task_queue_t queue;

static void *producer(void *argument)
{
    (void)argument;

    for (int i = 0; i < TEST_TASKS; i++) {
        task_t task;

        memset(&task, 0, sizeof(task));

        task.client_fd = 100 + i;

        snprintf(task.data,
                 sizeof(task.data),
                 "Task %d",
                 i + 1);

        task.data_length = strlen(task.data);

        task_queue_push(&queue, &task);

        printf("Produced: %s\n", task.data);
    }

    return NULL;
}

static void *consumer(void *argument)
{
    (void)argument;

    for (int i = 0; i < TEST_TASKS; i++) {
        task_t task;

        task_queue_pop(&queue, &task);

        printf("Consumed: %s (client_fd=%d)\n",
               task.data,
               task.client_fd);
    }

    return NULL;
}

int main(void)
{
    pthread_t producer_thread;
    pthread_t consumer_thread;

    if (task_queue_init(&queue) != 0) {
        fprintf(stderr, "Failed to initialize task queue\n");
        return 1;
    }

    pthread_create(&producer_thread,
                   NULL,
                   producer,
                   NULL);

    pthread_create(&consumer_thread,
                   NULL,
                   consumer,
                   NULL);

    pthread_join(producer_thread, NULL);
    pthread_join(consumer_thread, NULL);

    task_queue_destroy(&queue);

    printf("\nTask queue test PASSED\n");

    return 0;
}
