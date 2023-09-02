#include <stdio.h>
#include <stdlib.h>
#include "event.h"
#include "config.h"

#ifdef HAVE_KQUEUE
#include "event_kqueue.c"
#elif defined(HAVE_EPOLL)
#include "event_epoll.c"
#endif

EventLoop* create_event_loop(size_t max_events) {
    EventLoop *event_loop = calloc(1, sizeof(EventLoop));
    if(!event_loop) {
        perror("create_event_loop (calloc)");
        goto error;
    }

    event_loop->max_events = max_events;
    event_loop->events = malloc(sizeof(Event) * max_events);
    if(!event_loop->events) {
        perror("create_event_loop (malloc)");
        goto error;
    }

    if(!init_event_api(event_loop))
        goto error;

    return event_loop;
error:
    if(event_loop) {
        if(event_loop->events) free(event_loop->events);
        free(event_loop);
    }
    return NULL;
}

void free_event_loop(EventLoop *event_loop) {
    free_event_api(event_loop);
    free(event_loop->events);
    free(event_loop);
}
