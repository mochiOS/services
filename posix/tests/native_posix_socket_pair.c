#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr,                                                          \
              "posix-socket-pair: FAIL line=%u errno=%d condition=%s\n",       \
              __LINE__, errno, #condition);                                    \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static int blocking_fd;
static uint64_t find_process_label(const char *label) {
  uint64_t result;
  __asm__ volatile("syscall"
                   : "=a"(result)
                   : "a"(UINT64_C(518)), "D"((uint64_t)label),
                     "S"((uint64_t)strlen(label))
                   : "rcx", "r11", "memory");
  return result;
}

static int verify_exact_process_lookup(void) {
  CHECK(find_process_label("compositor.service") != 0);
  CHECK(find_process_label("compositor") == 0);
  CHECK(find_process_label("service") == 0);
  CHECK(find_process_label(".service") == 0);
  CHECK(find_process_label("compositor.service.elf") == 0);
  puts("native-process-exact-lookup: PASS");
  return 0;
}
static int verify_receive_capacity(void) {
  int fds[2];
  CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds) == 0);
  int alias = dup(fds[1]);
  CHECK(alias >= 0);
  int capacity = 1024;
  CHECK(setsockopt(alias, SOL_SOCKET, SO_RCVBUF, &capacity, sizeof(capacity)) ==
        0);
  socklen_t length = sizeof(capacity);
  capacity = -1;
  CHECK(getsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &capacity, &length) == 0 &&
        capacity == 1024);
  char data[1024];
  memset(data, 'd', sizeof(data));
  CHECK(write(fds[0], data, sizeof(data)) == sizeof(data));
  CHECK(write(fds[0], "x", 1) == -1 && errno == EAGAIN);
  capacity = 256;
  CHECK(setsockopt(alias, SOL_SOCKET, SO_RCVBUF, &capacity, sizeof(capacity)) ==
        0);
  CHECK(write(fds[0], "x", 1) == -1 && errno == EAGAIN);
  CHECK(read(fds[1], data, 769) == 769);
  for (unsigned i = 0; i < 769; ++i)
    CHECK(data[i] == 'd');
  CHECK(write(fds[0], "!more", 5) == 1);
  CHECK(read(alias, data, sizeof(data)) == 256 && data[255] == '!');
  for (unsigned i = 0; i < 255; ++i)
    CHECK(data[i] == 'd');
  memset(data, 'a', 256);
  CHECK(write(fds[0], data, 256) == 256);
  struct pollfd sender = {.fd = fds[0], .events = POLLOUT};
  CHECK(poll(&sender, 1, 0) == 0);
  capacity = 512;
  CHECK(setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &capacity,
                   sizeof(capacity)) == 0);
  CHECK(poll(&sender, 1, 0) == 1 && sender.revents == POLLOUT);
  CHECK(read(fds[1], data, sizeof(data)) == 256);
  capacity = -1;
  CHECK(setsockopt(alias, SOL_SOCKET, SO_RCVBUF, &capacity, sizeof(capacity)) ==
            -1 &&
        errno == EINVAL);
  CHECK(setsockopt(alias, SOL_SOCKET, SO_RCVBUF, NULL, sizeof(capacity)) ==
            -1 &&
        errno == EFAULT);
  CHECK(setsockopt(alias, SOL_SOCKET, SO_RCVBUF, &capacity, 1) == -1 &&
        errno == EINVAL);
  CHECK(setsockopt(alias, SOL_SOCKET, SO_TYPE, &capacity, sizeof(capacity)) ==
            -1 &&
        errno == ENOPROTOOPT);
  CHECK(setsockopt(-1, SOL_SOCKET, SO_RCVBUF, &capacity, sizeof(capacity)) ==
            -1 &&
        errno == EBADF);
  length = sizeof(capacity);
  CHECK(getsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &capacity, &length) == 0 &&
        capacity == 512);
  CHECK(close(alias) == 0 && close(fds[0]) == 0 && close(fds[1]) == 0);
  puts("posix-socket-receive-capacity: PASS");
  return 0;
}
static int verify_socket_errors(void) {
  for (int consume_by_read = 0; consume_by_read <= 1; ++consume_by_read) {
    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    int alias = dup(fds[0]);
    CHECK(alias >= 0);
    CHECK(write(fds[0], "discarded", 9) == 9);
    CHECK(write(fds[1], "kept", 4) == 4 && close(fds[1]) == 0);
    struct pollfd item = {.fd = fds[0], .events = POLLIN};
    unsigned tries;
    for (tries = 0; tries < 10000; ++tries) {
      CHECK(poll(&item, 1, 0) >= 0);
      if (item.revents & POLLERR)
        break;
      sched_yield();
    }
    CHECK(tries < 10000);
    int error = -1;
    socklen_t length = sizeof(error);
    CHECK(getsockopt(alias, SOL_SOCKET, SO_ERROR, NULL, &length) == -1 &&
          errno == EFAULT);
    char data[8];
    if (!consume_by_read) {
      CHECK(getsockopt(alias, SOL_SOCKET, SO_ERROR, &error, &length) == 0 &&
            error == ECONNRESET && length == sizeof(error));
    }
    CHECK(read(fds[0], data, sizeof(data)) == 4 && !memcmp(data, "kept", 4));
    if (consume_by_read) {
      CHECK(read(alias, data, sizeof(data)) == -1 && errno == ECONNRESET);
    }
    error = -1;
    length = sizeof(error);
    CHECK(getsockopt(fds[0], SOL_SOCKET, SO_ERROR, &error, &length) == 0 &&
          error == 0);
    CHECK(read(alias, data, sizeof(data)) == 0);
    item.events = 0;
    CHECK(poll(&item, 1, 0) == 1 && !(item.revents & POLLERR) &&
          (item.revents & POLLHUP));
    CHECK(close(alias) == 0 && close(fds[0]) == 0);
  }
  int fds[2];
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0 && close(fds[1]) == 0);
  int error = -1;
  socklen_t length = sizeof(error);
  CHECK(getsockopt(fds[0], SOL_SOCKET, SO_ERROR, &error, &length) == 0 &&
        error == 0);
  CHECK(close(fds[0]) == 0);
  puts("posix-socket-errors: PASS");
  return 0;
}
static int verify_socket_options(int fd, int accepting) {
  int value = -1;
  socklen_t length = sizeof(value);
  CHECK(getsockopt(fd, SOL_SOCKET, SO_TYPE, &value, &length) == 0 &&
        value == SOCK_STREAM && length == sizeof(value));
  length = sizeof(value);
  CHECK(getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &value, &length) == 0 &&
        value == accepting && length == sizeof(value));
  unsigned char truncated[2] = {0xff, 0xaa};
  length = 1;
  CHECK(getsockopt(fd, SOL_SOCKET, SO_TYPE, truncated, &length) == 0 &&
        length == 1 && truncated[0] == SOCK_STREAM && truncated[1] == 0xaa);
  length = 0;
  CHECK(getsockopt(fd, SOL_SOCKET, SO_TYPE, NULL, &length) == 0 && length == 0);
  length = sizeof(value);
  CHECK(getsockopt(fd, SOL_SOCKET, SO_TYPE, NULL, &length) == -1 &&
        errno == EFAULT);
  CHECK(getsockopt(fd, SOL_SOCKET, SO_TYPE, &value, NULL) == -1 &&
        errno == EFAULT);
  CHECK(getsockopt(fd, SOL_SOCKET, 999, &value, &length) == -1 &&
        errno == ENOPROTOOPT);
  CHECK(getsockopt(-1, SOL_SOCKET, SO_TYPE, &value, &length) == -1 &&
        errno == EBADF);
  return 0;
}
static int accept_started;
static int connect_started;
static int connect_fd;
static struct sockaddr_un connect_address;
static socklen_t connect_size;
static int connect_signals;
static void connect_signal(int signal) {
  (void)signal;
  __atomic_fetch_add(&connect_signals, 1, __ATOMIC_RELEASE);
}
static int await_pending_connect(int fd) {
  for (unsigned i = 0; i < 10000; ++i) {
    struct pollfd item = {.fd = fd, .events = POLLIN | POLLOUT};
    int ready = poll(&item, 1, 0);
    if (ready == 0)
      return 0;
    CHECK(ready == 1);
    sched_yield();
  }
  CHECK(0 && "connect did not enter backlog wait");
  return 1;
}
static void *waiting_connector(void *unused) {
  (void)unused;
  __atomic_store_n(&connect_started, 1, __ATOMIC_RELEASE);
  int result =
      connect(connect_fd, (struct sockaddr *)&connect_address, connect_size);
  return (void *)(intptr_t)(result == 0 ? 1 : -errno);
}

static int verify_connect_interrupts(void) {
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  strcpy(address.sun_path, "/native-posix-connect-signals");
  socklen_t size = 2 + strlen(address.sun_path) + 1;
  CHECK(unlink(address.sun_path) == 0 || errno == ENOENT);
  int listener = socket(AF_UNIX, SOCK_STREAM, 0);
  CHECK(listener >= 0 &&
        bind(listener, (struct sockaddr *)&address, size) == 0);
  CHECK(listen(listener, 1) == 0);
  struct sigaction action = {.sa_handler = connect_signal}, previous;
  CHECK(sigemptyset(&action.sa_mask) == 0);
  CHECK(sigaction(SIGUSR1, &action, &previous) == 0);
  for (int restart = 0; restart <= 1; ++restart) {
    action.sa_flags = restart ? SA_RESTART : 0;
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    int first = socket(AF_UNIX, SOCK_STREAM, 0);
    int client = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(first >= 0 && client >= 0);
    CHECK(connect(first, (struct sockaddr *)&address, size) == 0);
    connect_fd = client;
    connect_address = address;
    connect_size = size;
    __atomic_store_n(&connect_signals, 0, __ATOMIC_RELEASE);
    pthread_t worker;
    CHECK(pthread_create(&worker, NULL, waiting_connector, NULL) == 0);
    CHECK(await_pending_connect(client) == 0);
    CHECK(pthread_kill(worker, SIGUSR1) == 0);
    unsigned tries;
    for (tries = 0;
         tries < 10000 && !__atomic_load_n(&connect_signals, __ATOMIC_ACQUIRE);
         ++tries)
      sched_yield();
    CHECK(tries < 10000);
    void *result;
    if (!restart) {
      CHECK(pthread_join(worker, &result) == 0 &&
            result == (void *)(intptr_t)-EINTR);
    } else {
      struct pollfd pending = {.fd = client, .events = POLLIN | POLLOUT};
      CHECK(poll(&pending, 1, 0) == 0);
    }
    int accepted = accept(listener, NULL, NULL);
    CHECK(accepted >= 0);
    if (restart) {
      CHECK(pthread_join(worker, &result) == 0 && result == (void *)1);
    } else {
      struct sockaddr_un peer;
      socklen_t length = sizeof(peer);
      CHECK(getpeername(client, (struct sockaddr *)&peer, &length) == -1 &&
            errno == ENOTCONN);
      struct pollfd empty = {.fd = listener, .events = POLLIN};
      CHECK(poll(&empty, 1, 0) == 0);
      CHECK(connect(client, (struct sockaddr *)&address, size) == 0);
    }
    int retried = accept(listener, NULL, NULL);
    CHECK(retried >= 0);
    CHECK(write(client, "ok", 2) == 2);
    char data[2];
    CHECK(read(retried, data, 2) == 2 && !memcmp(data, "ok", 2));
    CHECK(close(first) == 0 && close(client) == 0 && close(accepted) == 0 &&
          close(retried) == 0);
  }
  CHECK(sigaction(SIGUSR1, &previous, NULL) == 0);
  puts("posix-socket-connect-signals: PASS");

  int first = socket(AF_UNIX, SOCK_STREAM, 0);
  int doomed = socket(AF_UNIX, SOCK_STREAM, 0);
  CHECK(first >= 0 && doomed >= 0);
  CHECK(connect(first, (struct sockaddr *)&address, size) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    close(listener);
    close(first);
    connect(doomed, (struct sockaddr *)&address, size);
    _exit(91);
  }
  CHECK(await_pending_connect(doomed) == 0);
  CHECK(kill(child, SIGKILL) == 0);
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
        WTERMSIG(status) == SIGKILL);
  unsigned tries;
  for (tries = 0; tries < 10000; ++tries) {
    struct pollfd state = {.fd = doomed, .events = POLLIN | POLLOUT};
    if (poll(&state, 1, 0) == 1)
      break;
    sched_yield();
  }
  CHECK(tries < 10000);
  int accepted = accept(listener, NULL, NULL);
  CHECK(accepted >= 0);
  struct pollfd empty = {.fd = listener, .events = POLLIN};
  CHECK(poll(&empty, 1, 0) == 0);
  CHECK(connect(doomed, (struct sockaddr *)&address, size) == 0);
  int retried = accept(listener, NULL, NULL);
  CHECK(retried >= 0);
  CHECK(close(first) == 0 && close(doomed) == 0 && close(accepted) == 0 &&
        close(retried) == 0);
  CHECK(close(listener) == 0 && unlink(address.sun_path) == 0);
  puts("posix-socket-connect-process-exit: PASS");
  return 0;
}

static int verify_connections(int listener, struct sockaddr_un *address,
                              socklen_t size) {
  CHECK(listen(listener, 1) == 0);
  int receive_capacity = 4096;
  CHECK(setsockopt(listener, SOL_SOCKET, SO_RCVBUF, &receive_capacity,
                   sizeof(receive_capacity)) == 0);
  int first = socket(AF_UNIX, SOCK_STREAM, 0);
  int second = socket(AF_UNIX, SOCK_STREAM, 0);
  CHECK(first >= 0 && second >= 0);
  CHECK(verify_socket_options(first, 0) == 0 &&
        verify_socket_options(listener, 1) == 0);
  CHECK(connect(-1, (struct sockaddr *)address, size) == -1 && errno == EBADF);
  CHECK(connect(first, NULL, size) == -1 && errno == EFAULT);
  CHECK(connect(first, (struct sockaddr *)address, size) == 0);
  CHECK(connect(first, (struct sockaddr *)address, size) == -1 &&
        errno == EISCONN);
  struct pollfd ready = {.fd = listener, .events = POLLIN};
  CHECK(poll(&ready, 1, 0) == 1 && ready.revents == POLLIN);
  CHECK(write(first, "before", 6) == 6);
  CHECK(fcntl(second, F_SETFL, O_NONBLOCK) == 0);
  CHECK(connect(second, (struct sockaddr *)address, size) == -1 &&
        errno == EAGAIN);
  CHECK(fcntl(second, F_SETFL, 0) == 0);
  connect_fd = second;
  connect_address = *address;
  connect_size = size;
  __atomic_store_n(&connect_started, 0, __ATOMIC_RELEASE);
  pthread_t worker;
  CHECK(pthread_create(&worker, NULL, waiting_connector, NULL) == 0);
  while (!__atomic_load_n(&connect_started, __ATOMIC_ACQUIRE))
    sched_yield();
  for (unsigned i = 0; i < 100; ++i)
    sched_yield();
  void *result;
  CHECK(pthread_cancel(worker) == 0);
  CHECK(pthread_join(worker, &result) == 0 && result == PTHREAD_CANCELED);
  // A cancelled attempt must not connect when backlog space becomes free.
  struct sockaddr_un peer;
  socklen_t length = sizeof(peer);
  int accepted = accept4(listener, (struct sockaddr *)&peer, &length,
                         SOCK_NONBLOCK | SOCK_CLOEXEC);
  CHECK(accepted >= 0 && length == 2 && peer.sun_family == AF_UNIX);
  socklen_t capacity_length = sizeof(receive_capacity);
  CHECK(getsockopt(accepted, SOL_SOCKET, SO_RCVBUF, &receive_capacity,
                   &capacity_length) == 0 &&
        receive_capacity == 4096);
  CHECK(verify_socket_options(accepted, 0) == 0);
  CHECK((fcntl(accepted, F_GETFL, 0) & O_NONBLOCK) != 0);
  CHECK((fcntl(accepted, F_GETFD, 0) & FD_CLOEXEC) != 0);
  char data[8];
  CHECK(read(accepted, data, sizeof(data)) == 6 && !memcmp(data, "before", 6));
  CHECK(write(accepted, "reply", 5) == 5);
  CHECK(read(first, data, sizeof(data)) == 5 && !memcmp(data, "reply", 5));
  length = sizeof(peer);
  CHECK(getpeername(first, (struct sockaddr *)&peer, &length) == 0 &&
        length == size && !strcmp(peer.sun_path, address->sun_path));
  CHECK(getpeername(second, (struct sockaddr *)&peer, &length) == -1 &&
        errno == ENOTCONN);
  CHECK(connect(second, (struct sockaddr *)address, size) == 0);
  int third = socket(AF_UNIX, SOCK_STREAM, 0);
  CHECK(third >= 0);
  connect_fd = third;
  __atomic_store_n(&connect_started, 0, __ATOMIC_RELEASE);
  CHECK(pthread_create(&worker, NULL, waiting_connector, NULL) == 0);
  while (!__atomic_load_n(&connect_started, __ATOMIC_ACQUIRE))
    sched_yield();
  for (unsigned i = 0; i < 100; ++i)
    sched_yield();
  int accepted_second = accept(listener, NULL, NULL);
  CHECK(accepted_second >= 0);
  CHECK(pthread_join(worker, &result) == 0 && result == (void *)1);
  int accepted_third = accept(listener, NULL, NULL);
  CHECK(accepted_third >= 0 &&
        (fcntl(accepted_third, F_GETFL, 0) & O_NONBLOCK) == 0);
  CHECK(write(third, "last", 4) == 4 &&
        read(accepted_third, data, sizeof(data)) == 4);
  CHECK(close(first) == 0 && close(second) == 0 && close(third) == 0);
  CHECK(close(accepted) == 0 && close(accepted_second) == 0 &&
        close(accepted_third) == 0);
  puts("posix-socket-connect-accept: PASS");
  return 0;
}
static void *empty_acceptor(void *argument) {
  __atomic_store_n(&accept_started, 1, __ATOMIC_RELEASE);
  int fd = accept((int)(intptr_t)argument, NULL, NULL);
  if (fd >= 0)
    close(fd);
  return (void *)1;
}
static int verify_path_binding(void) {
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  strcpy(address.sun_path, "/native-posix-bound");
  socklen_t size = 2 + strlen(address.sun_path) + 1;
  CHECK(unlink(address.sun_path) == 0 || errno == ENOENT);
  int a = socket(AF_UNIX, SOCK_STREAM, 0);
  int b = socket(AF_UNIX, SOCK_STREAM, 0);
  CHECK(a >= 0 && b >= 0);
  CHECK(accept(-1, NULL, NULL) == -1 && errno == EBADF);
  CHECK(accept(b, NULL, NULL) == -1 && errno == EINVAL);
  CHECK(listen(-1, 1) == -1 && errno == EBADF);
  CHECK(listen(b, 1) == -1 && errno == EINVAL);
  CHECK(bind(-1, (struct sockaddr *)&address, size) == -1 && errno == EBADF);
  CHECK(bind(a, NULL, size) == -1 && errno == EFAULT);
  CHECK(bind(a, (struct sockaddr *)&address, size) == 0);
  CHECK(listen(a, SOMAXCONN) == 0 && listen(a, -1) == 0 &&
        listen(a, 0x7fffffff) == 0);
  struct pollfd listener = {.fd = a, .events = POLLIN | POLLOUT};
  CHECK(poll(&listener, 1, 0) == 0 && listener.revents == 0);
  int original_flags = fcntl(a, F_GETFL, 0);
  CHECK(fcntl(a, F_SETFL, original_flags | O_NONBLOCK) == 0);
  CHECK(accept(a, NULL, NULL) == -1 && errno == EAGAIN);
  CHECK(accept4(a, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK) == -1 &&
        errno == EAGAIN);
  CHECK(accept4(a, NULL, NULL, 0x1000) == -1 && errno == EINVAL);
  CHECK(fcntl(a, F_SETFL, original_flags) == 0);
  int expected_free = dup(b);
  CHECK(expected_free >= 0 && close(expected_free) == 0);
  pthread_t waiter;
  CHECK(pthread_create(&waiter, NULL, empty_acceptor, (void *)(intptr_t)a) ==
        0);
  while (!__atomic_load_n(&accept_started, __ATOMIC_ACQUIRE))
    sched_yield();
  for (unsigned index = 0; index < 100; ++index)
    sched_yield();
  CHECK(pthread_cancel(waiter) == 0);
  void *waited;
  CHECK(pthread_join(waiter, &waited) == 0 && waited == PTHREAD_CANCELED);
  int reused_free = dup(b);
  CHECK(reused_free == expected_free && close(reused_free) == 0);
  puts("posix-socket-accept-empty: PASS");
  CHECK(verify_connections(a, &address, size) == 0);
  CHECK(bind(a, (struct sockaddr *)&address, size) == -1 && errno == EINVAL);
  CHECK(bind(b, (struct sockaddr *)&address, size) == -1 &&
        errno == EADDRINUSE);
  struct sockaddr_un actual;
  socklen_t length = sizeof(actual);
  CHECK(getsockname(a, (struct sockaddr *)&actual, &length) == 0 &&
        length == size && actual.sun_family == AF_UNIX &&
        !strcmp(actual.sun_path, address.sun_path));
  int alias = dup(a);
  CHECK(alias >= 0 && close(a) == 0);
  CHECK(listen(alias, 4) == 0);
  listener.fd = alias;
  CHECK(poll(&listener, 1, 0) == 0 && listener.revents == 0);
  CHECK(unlink(address.sun_path) == 0);
  CHECK(bind(b, (struct sockaddr *)&address, size) == 0);
  length = sizeof(actual);
  CHECK(getsockname(alias, (struct sockaddr *)&actual, &length) == 0 &&
        !strcmp(actual.sun_path, address.sun_path));
  CHECK(close(alias) == 0);
  int c = socket(AF_UNIX, SOCK_STREAM, 0);
  CHECK(c >= 0);
  CHECK(bind(c, (struct sockaddr *)&address, size) == -1 &&
        errno == EADDRINUSE);
  CHECK(close(b) == 0);
  CHECK(bind(c, (struct sockaddr *)&address, size) == -1 &&
        errno == EADDRINUSE);
  CHECK(unlink(address.sun_path) == 0);
  // Relative spelling uses the retained cwd, not a second string-key namespace.
  CHECK(chdir("/") == 0);
  strcpy(address.sun_path, "native-posix-bound");
  size = 2 + strlen(address.sun_path) + 1;
  CHECK(bind(c, (struct sockaddr *)&address, size) == 0);
  CHECK(close(c) == 0 && unlink("/native-posix-bound") == 0);
  puts("posix-socket-bind: PASS");
  return 0;
}
static int verify_single_socket(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  CHECK(fd >= 0 && fcntl(fd, F_GETFD, 0) == FD_CLOEXEC);
  CHECK(fcntl(fd, F_GETFL, 0) == (O_RDWR | O_NONBLOCK));
  struct stat status;
  CHECK(fstat(fd, &status) == 0 && S_ISSOCK(status.st_mode));
  CHECK(status.st_uid == geteuid() && status.st_gid == getegid());
  struct sockaddr address;
  socklen_t length = sizeof(address);
  CHECK(getsockname(fd, &address, &length) == 0 && length == 2 &&
        address.sa_family == AF_UNIX);
  length = sizeof(address);
  CHECK(getpeername(fd, &address, &length) == -1 && errno == ENOTCONN);
  char byte;
  CHECK(read(fd, &byte, 1) == -1 && errno == ENOTCONN);
  CHECK(send(fd, "x", 1, MSG_NOSIGNAL) == -1 && errno == ENOTCONN);
  CHECK(shutdown(fd, SHUT_RDWR) == -1 && errno == ENOTCONN);
  int alias = dup(fd);
  CHECK(alias >= 0 && fcntl(alias, F_GETFD, 0) == 0);
  CHECK(fcntl(alias, F_SETFL, 0) == 0 && fcntl(fd, F_GETFL, 0) == O_RDWR);
  CHECK(close(fd) == 0);
  length = sizeof(address);
  CHECK(getsockname(alias, &address, &length) == 0 && length == 2);
  CHECK(close(alias) == 0);
  CHECK(socket(AF_INET, SOCK_STREAM, 0) == -1 && errno == ENOTSUP);
  return 0;
}
static int verify_names(int fd) {
  for (int peer = 0; peer < 2; ++peer) {
    struct sockaddr address;
    memset(&address, 0xff, sizeof(address));
    socklen_t length = sizeof(address);
    int result = peer ? getpeername(fd, &address, &length)
                      : getsockname(fd, &address, &length);
    CHECK(result == 0 && length == sizeof(sa_family_t) &&
          address.sa_family == AF_UNIX &&
          (unsigned char)address.sa_data[0] == 0xff);
    unsigned char bytes[4] = {0xfe, 0xfe, 0xfe, 0xfe};
    length = 1;
    result = peer ? getpeername(fd, (struct sockaddr *)bytes, &length)
                  : getsockname(fd, (struct sockaddr *)bytes, &length);
    CHECK(result == 0 && length == 2 && bytes[0] == AF_UNIX &&
          bytes[1] == 0xfe);
    bytes[0] = 0xfe;
    length = 0;
    result = peer ? getpeername(fd, (struct sockaddr *)bytes, &length)
                  : getsockname(fd, (struct sockaddr *)bytes, &length);
    CHECK(result == 0 && length == 2 && bytes[0] == 0xfe);
  }
  socklen_t length = 16;
  struct sockaddr address;
  CHECK(getsockname(fd, NULL, &length) == -1 && errno == EFAULT);
  CHECK(getpeername(fd, &address, NULL) == -1 && errno == EFAULT);
  CHECK(getsockname(-1, &address, &length) == -1 && errno == EBADF);
  CHECK(getpeername(1, &address, &length) == -1 && errno == ENOTSOCK);
  return 0;
}
static volatile int started;
static void *reader(void *unused) {
  (void)unused;
  __atomic_store_n(&started, 1, __ATOMIC_RELEASE);
  char bytes[4];
  return recv(blocking_fd, bytes, sizeof(bytes), MSG_WAITALL) == 4 &&
                 !memcmp(bytes, "z123", 4)
             ? NULL
             : (void *)1;
}
static int verify_exec(char **argv) {
  int a = atoi(argv[2]), b = atoi(argv[3]), closed = atoi(argv[4]);
  CHECK(fcntl(closed, F_GETFD, 0) == -1 && errno == EBADF);
  CHECK(fcntl(a, F_GETFD, 0) == 0 && fcntl(b, F_GETFD, 0) == 0);
  CHECK(fcntl(a, F_GETFL, 0) == (O_RDWR | O_NONBLOCK));
  CHECK(verify_names(a) == 0 && verify_names(b) == 0);
  struct stat left, right;
  CHECK(fstat(a, &left) == 0 && fstat(b, &right) == 0);
  CHECK(S_ISSOCK(left.st_mode) && S_ISSOCK(right.st_mode));
  CHECK(left.st_dev == right.st_dev && left.st_ino != right.st_ino);
  char bytes[8];
  CHECK(write(b, "exec", 4) == 4);
  CHECK(read(a, bytes, sizeof(bytes)) == 4 && !memcmp(bytes, "exec", 4));
  CHECK(fcntl(a, F_SETFL, 0) == 0);
  fprintf(stderr, "posix-socket-pair-exec: PASS\n");
  return 0;
}
int main(int argc, char **argv) {
  if (argc == 5 && !strcmp(argv[1], "--socket-exec"))
    return verify_exec(argv);
  CHECK(verify_single_socket() == 0);
  CHECK(verify_path_binding() == 0);
  CHECK(verify_exact_process_lookup() == 0);
  CHECK(verify_receive_capacity() == 0);
  CHECK(verify_socket_errors() == 0);
  puts("posix-socket-options: PASS");
  CHECK(verify_connect_interrupts() == 0);
  int fds[2] = {123, 456};
  CHECK(socketpair(AF_UNIX, SOCK_STREAM | 0x1000, 0, fds) == -1 &&
        errno == EINVAL);
  CHECK(fds[0] == 123 && fds[1] == 456);
  struct rlimit original_limit, exhausted;
  CHECK(getrlimit(RLIMIT_NOFILE, &original_limit) == 0);
  exhausted = original_limit;
  exhausted.rlim_cur = 0;
  CHECK(setrlimit(RLIMIT_NOFILE, &exhausted) == 0);
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == -1 && errno == EMFILE);
  CHECK(fds[0] == 123 && fds[1] == 456);
  CHECK(setrlimit(RLIMIT_NOFILE, &original_limit) == 0);
  CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                   fds) == 0);
  int a = fds[0], b = fds[1];
  CHECK(fcntl(a, F_GETFD, 0) == FD_CLOEXEC &&
        fcntl(b, F_GETFD, 0) == FD_CLOEXEC);
  CHECK(fcntl(a, F_GETFL, 0) == (O_RDWR | O_NONBLOCK));
  int alias = dup(a);
  CHECK(verify_names(a) == 0 && verify_names(b) == 0);
  CHECK(alias >= 0 && fcntl(alias, F_GETFD, 0) == 0);
  struct stat original, duplicate, other;
  CHECK(fstat(a, &original) == 0 && fstat(alias, &duplicate) == 0 &&
        fstat(b, &other) == 0);
  CHECK(S_ISSOCK(original.st_mode) && original.st_dev == duplicate.st_dev &&
        original.st_ino == duplicate.st_ino);
  CHECK(original.st_ino != other.st_ino && original.st_uid == geteuid() &&
        original.st_gid == getegid());
  CHECK(fcntl(alias, F_SETFL, 0) == 0 && fcntl(a, F_GETFL, 0) == O_RDWR);
  char empty_byte;
  CHECK(recv(a, &empty_byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
  CHECK(fcntl(a, F_GETFL, 0) == O_RDWR && fcntl(alias, F_GETFL, 0) == O_RDWR);
  CHECK(fcntl(b, F_GETFL, 0) == (O_RDWR | O_NONBLOCK));
  CHECK(fcntl(a, F_SETFL, O_NONBLOCK) == 0);
  char bytes[8];
  CHECK(read(a, bytes, 1) == -1 && errno == EAGAIN);
  CHECK(lseek(a, 0, SEEK_CUR) == -1 && errno == ESPIPE);
  struct pollfd item = {a, POLLIN | POLLOUT | POLLPRI, 0};
  CHECK(poll(&item, 1, 0) == 1 && item.revents == POLLOUT);
  item.events = POLLIN;
  CHECK(poll(&item, 1, 0) == 0 && item.revents == 0);
  CHECK(send(b, "hello", 5, MSG_NOSIGNAL) == 5);
  CHECK(recv(a, bytes, sizeof(bytes), MSG_PEEK) == -1 && errno == ENOTSUP);
  CHECK(fstat(a, &duplicate) == 0 && duplicate.st_size == 0 &&
        duplicate.st_ino == original.st_ino);
  CHECK(poll(&item, 1, 0) == 1 && item.revents == POLLIN);
  fd_set reads, writes, exceptions;
  FD_ZERO(&reads);
  FD_ZERO(&writes);
  FD_ZERO(&exceptions);
  FD_SET(a, &reads);
  FD_SET(a, &writes);
  FD_SET(a, &exceptions);
  struct timeval timeout = {0, 0};
  CHECK(select(a + 1, &reads, &writes, &exceptions, &timeout) == 2);
  CHECK(FD_ISSET(a, &reads) && FD_ISSET(a, &writes) &&
        !FD_ISSET(a, &exceptions));
  CHECK(read(alias, bytes, 3) == 3 && !memcmp(bytes, "hel", 3));
  CHECK(read(a, bytes, 8) == 2 && !memcmp(bytes, "lo", 2));
  CHECK(fcntl(b, F_SETFD, 0) == 0);
  char alias_arg[16], b_arg[16], closed_arg[16];
  snprintf(alias_arg, sizeof(alias_arg), "%d", alias);
  snprintf(b_arg, sizeof(b_arg), "%d", b);
  snprintf(closed_arg, sizeof(closed_arg), "%d", a);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    char *arguments[] = {"socket-test", "--socket-exec", alias_arg,
                         b_arg,         closed_arg,      NULL};
    char *environment[] = {NULL};
    execve("/system/services/compositor.service", arguments, environment);
    _exit(90);
  }
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  CHECK(fcntl(a, F_GETFL, 0) == O_RDWR);
  CHECK(fcntl(a, F_SETFL, O_NONBLOCK) == 0);
  CHECK(shutdown(b, SHUT_WR) == 0);
  CHECK(read(a, bytes, 1) == 0);
  CHECK(write(a, "x", 1) == 1 && read(b, bytes, 1) == 1 && bytes[0] == 'x');
  CHECK(send(b, "x", 1, MSG_NOSIGNAL) == -1 && errno == EPIPE);
  CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
  CHECK(write(b, "x", 1) == -1 && errno == EPIPE);
  item.fd = b;
  item.events = POLLOUT;
  CHECK(poll(&item, 1, 0) == 1 && item.revents == POLLOUT);
  item.events = 0;
  CHECK(poll(&item, 1, 0) == 0 && item.revents == 0);
  CHECK(close(a) == 0 && close(alias) == 0);
  CHECK(close(b) == 0);
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
  blocking_fd = fds[0];
  pthread_t thread;
  CHECK(pthread_create(&thread, NULL, reader, NULL) == 0);
  while (!__atomic_load_n(&started, __ATOMIC_ACQUIRE))
    sched_yield();
  for (unsigned index = 0; index < 100; ++index)
    sched_yield();
  CHECK(send(fds[1], "z1", 2, 0) == 2);
  for (unsigned index = 0; index < 100; ++index)
    sched_yield();
  CHECK(send(fds[1], "23", 2, 0) == 2);
  void *result;
  CHECK(pthread_join(thread, &result) == 0 && result == NULL);
  CHECK(close(fds[1]) == 0);
  CHECK(verify_names(fds[0]) == 0);
  CHECK(close(fds[0]) == 0);
  puts("posix-socket-pair: PASS");
  return 0;
}
