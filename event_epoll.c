#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/epoll.h>

typedef struct {
    int                epfd;
    struct epoll_event *events;
} EpollData;

bool init_event_api(EventLoop *event_loop) {
    EpollData *data = malloc(sizeof(EpollData));
    if(!data) {
        perror("init_event_api (epoll) (malloc)");
        goto error;
    }

    data->events = malloc(sizeof(struct epoll_event) * event_loop->max_events);
    if(!data->events) {
        perror("init_event_api (epoll) (malloc)");
        goto error;
    }

    data->epfd = epoll_create(256);
    if(data->epfd < 0) {
        perror("init_event_api (epoll) (epoll_create)");
        goto error;
    }

    event_loop->api_data = data;
    return true;
error:
    if(data) {
        if(data->events) free(data->events);
        free(data);
    }
    return false;
}

void free_event_api(EventLoop *event_loop) {
    EpollData *data = event_loop->api_data;
    close(data->epfd);
    free(data->events);
    free(data);
}

int poll_events(EventLoop *event_loop, const struct timespec *tv) {
    EpollData *data = event_loop->api_data;

    int timeout;
    if(!tv)
        timeout = -1;
    else
        timeout = tv->tv_sec * 1000 + tv->tv_nsec / 1000000;

    int num_events = epoll_wait(
        data->epfd,
        data->events,
        event_loop->max_events,
        timeout
    );
    if(num_events < 0) {
        perror("poll_events (epoll) (epoll_wait)");
        return -1;
    }

    for(int i = 0; i < num_events; i++) {
        int mask = 0;
        uint32_t events = data->events[i].events;
        if(events & EPOLLIN)
            mask |= EVENT_READ;
        if(events & EPOLLOUT)
            mask |= EVENT_WRITE;

        event_loop->events[i].fd = data->events[i].data.fd;
        event_loop->events[i].mask = mask;
    }

    return num_events;
}

bool set_event_mask(EventLoop *event_loop, int fd, int mask, bool is_modify) {
    EpollData *data = event_loop->api_data;

    int op = is_modify ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
    struct epoll_event event;

    event.data.fd = fd;
    event.events = 0;
    if(mask & EVENT_READ)
        event.events |= EPOLLIN;
    if(mask & EVENT_WRITE)
        event.events |= EPOLLOUT;

    if(epoll_ctl(data->epfd, op, fd, &event) < 0) {
        perror("set_event_mask (epoll) (epoll_ctl)");
        return false;
    }

    return true;
}
