#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <time.h>

#define EVENT_NONE  0x0
#define EVENT_READ  0x1
#define EVENT_WRITE 0x2

typedef struct {
    int fd;
    int mask;
} Event;

typedef struct {
    size_t max_events;
    Event  *events;
    void   *api_data;
} EventLoop;

EventLoop* create_event_loop(size_t max_events);
int poll_events(EventLoop *event_loop, const struct timespec *tv);
bool set_event_mask(EventLoop *event_loop, int fd, int mask, bool is_modify);
void free_event_loop(EventLoop *event_loop);
