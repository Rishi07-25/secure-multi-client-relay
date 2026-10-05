#ifndef FRAME_IO_H
#define FRAME_IO_H

#include "connection.h"

#include <stddef.h>

#define FRAME_IO_INCOMPLETE 0
#define FRAME_IO_COMPLETE   1
#define FRAME_IO_CLOSED     2
#define FRAME_IO_ERROR     -1

int recv_protocol_frame(
    connection_t *connection,
    unsigned char *frame,
    size_t frame_capacity,
    size_t *frame_length
);

int send_all_bytes(
    int fd,
    const unsigned char *data,
    size_t length
);

#endif
