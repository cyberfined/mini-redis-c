#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/event.h>
#include "event.h"

typedef struct {
    int           kq;
    struct kevent *event_list;
    uintmax_t    *fd_info;
} KqueueData;

bool init_event_api(EventLoop *event_loop) {
    KqueueData *data = calloc(1, sizeof(KqueueData));
    if(!data) {
        perror("init_event_api (kqueue) (calloc)");
        goto error;
    }

    data->event_list = malloc(sizeof(struct kevent) * event_loop->max_events);
    if(!data->event_list) {
        perror("init_event_api (kqueue) (malloc)");
        goto error;
    }

    size_t bitvec_size = event_loop->max_events / (4 * sizeof(uintmax_t));
    if(bitvec_size * 4 * sizeof(uintmax_t) < event_loop->max_events)
        bitvec_size++;
    data->fd_info = calloc(bitvec_size, sizeof(uintmax_t));
    if(!data->fd_info) {
        perror("init_event_api (kqueue) (calloc)");
        goto error;
    }

    data->kq = kqueue();
    if(data->kq < 0) {
        perror("init_event_api (kqueue)");
        goto error;
    }

    event_loop->api_data = data;
    return true;
error:
    if(data) {
        if(data->event_list) free(data->event_list);
        if(data->fd_info) free(data->fd_info);
        free(data);
    }
    return false;
}

void free_event_api(EventLoop *event_loop) {
    KqueueData *data = event_loop->api_data;
    close(data->kq);
    free(data->event_list);
    free(data->fd_info);
    free(data);
}

int poll_events(EventLoop *event_loop, int timeout) {
    KqueueData *data = event_loop->api_data;

    struct timespec tp, *tp_ptr;
    if(timeout < 0) {
        tp_ptr = NULL;
    } else {
        tp.tv_sec = timeout / 1000;
        tp.tv_nsec = timeout - tp.tv_sec * 1000;
        tp_ptr = &tp;
    }

    int num_events = kevent(
        data->kq,
        NULL, 0,
        data->event_list, event_loop->max_events,
        tp_ptr
    );
    if(num_events < 0) {
        perror("poll_events (kqueue) (kevent)");
        return -1;
    }

    for(int i = 0; i < num_events; i++) {
        int mask = 0;
        int16_t filter = data->event_list[i].filter;
        if(filter == EVFILT_READ)
            mask = EVENT_READ;
        else if(filter == EVFILT_WRITE)
            mask = EVENT_WRITE;
        event_loop->events[i].fd = data->event_list[i].ident;
        event_loop->events[i].mask = mask;
    }

    return num_events;
}

bool set_event_mask(EventLoop *event_loop, int fd, int mask, bool is_modify) {
    KqueueData *data = event_loop->api_data;

    struct kevent events[2];
    memset(&events, 0, sizeof(events));
    events[0].ident = fd;
    int nchanges;

    int double_fd = 2 * fd;
    int vec_index = double_fd / (8 * sizeof(uintmax_t));
    int read_event_registered_bit = double_fd & (8 * sizeof(uintmax_t) - 1);
    int write_event_registered_bit = read_event_registered_bit + 1;
    uintmax_t vec_segment = data->fd_info[vec_index];

    if(is_modify) {
        nchanges = 2;
        events[1].ident = fd;
        events[1].flags = EV_DISABLE;

        if(mask == EVENT_READ) {
            if(vec_segment & (1 << read_event_registered_bit)) {
                events[0].flags = EV_ENABLE;
            } else {
                events[0].flags = EV_ADD;
                vec_segment |= (1 << read_event_registered_bit);
                data->fd_info[vec_index] = vec_segment;
            }

            events[0].filter = EVFILT_READ;
            events[1].filter = EVFILT_WRITE;
        } else if(mask == EVENT_WRITE) {
            if(vec_segment & (1 << write_event_registered_bit)) {
                events[0].flags = EV_ENABLE;
            } else {
                events[0].flags = EV_ADD;
                vec_segment |= (1 << write_event_registered_bit);
                data->fd_info[vec_index] = vec_segment;
            }

            events[0].filter = EVFILT_WRITE;
            events[1].filter = EVFILT_READ;
        }
    } else {
        nchanges = 1;
        events[0].flags = EV_ADD;
        if(mask == EVENT_READ) {
            events[0].filter = EVFILT_READ;
            vec_segment |= (1 << read_event_registered_bit);
            vec_segment &= ~(1 << write_event_registered_bit);
        } else if(mask == EVENT_WRITE) {
            events[0].filter = EVFILT_WRITE;
            vec_segment |= (1 << write_event_registered_bit);
            vec_segment &= ~(1 << read_event_registered_bit);
        }
        data->fd_info[vec_index] = vec_segment;
    }

    if(kevent(data->kq, events, nchanges, NULL, 0, NULL) < 0) {
        perror("set_event_mask (kqueue) (kevent)");
        return false;
    }

    return true;
}
