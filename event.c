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
    EventLoop *event_loop = malloc(sizeof(EventLoop));
    if(!event_loop) {
        perror("create_event_loop (malloc)");
        return NULL;
    }

    event_loop->max_events = max_events;
    event_loop->events = malloc(sizeof(Event) * max_events);
    if(!event_loop->events) {
        perror("create_event_loop (malloc)");
        return NULL;
    }

    if(!init_event_api(event_loop))
        return NULL;

    return event_loop;
}

void free_event_loop(EventLoop *event_loop) {
    free_event_api(event_loop);
    free(event_loop->events);
    free(event_loop);
}
