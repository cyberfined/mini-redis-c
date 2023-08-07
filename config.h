#pragma once

#ifdef __APPLE__
#define HAVE_KQUEUE 1
#elif defined(__linux__)
#define HAVE_EPOLL 1
#define HAVE_SOCK_NONBLOCK 1
#endif
