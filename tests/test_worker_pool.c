#include "worker_pool.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    task_queue_t queue;
    worker_pool_t pool;

    if (task_queue_init(&queue) != 0) {
        fprintf(stderr, "Failed to initialize queue\n");
        return 1;
    }

    if (worker_pool_init(&pool, &queue) != 0) {
        fprintf(stderr, "Failed to initialize worker pool\n");
        task_queue_destroy(&queue);
        return 1;
    }

    for (int i = 0; i < 12; i++) {
        task_t task;

        memset(&task, 0, sizeof(task));

        task.client_fd = 200 + i;

        snprintf(task.data,
                 sizeof(task.data),
                 "Worker task %d",
                 i + 1);

        task.data_length = strlen(task.data);

        task_queue_push(&queue, &task);
    }

    sleep(2);

    printf("\nWorker pool test completed\n");

    return 0;
}
