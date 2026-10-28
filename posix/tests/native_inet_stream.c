#define _GNU_SOURCE 1
#define _POSIX_THREADS 1
#define _POSIX_TIMERS 1
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static __thread unsigned cookie = 17;
static void check(int condition, unsigned line) {
  if (!condition) {
    fprintf(stderr, "inet-stream: FAIL line=%u errno=%d euid=%u\n", line, errno,
            (unsigned)geteuid());
    exit(1);
  }
}
#define CHECK(x) check(!!(x), __LINE__)
static void delay(void) {
  struct timespec t = {0, 10000000};
  CHECK(nanosleep(&t, NULL) == 0);
}
static struct sockaddr_in endpoint;
static int option(int fd, int tag) {
  int n = -1;
  socklen_t size = sizeof(n);
  CHECK(getsockopt(fd, SOL_SOCKET, tag, &n, &size) == 0 && size == sizeof(n));
  return n;
}
static int listener(int backlog) {
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  CHECK(fd >= 0);
  memset(&endpoint, 0, sizeof(endpoint));
  endpoint.sin_family = AF_INET;
  endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(bind(fd, (struct sockaddr *)&endpoint, sizeof(endpoint)) == 0);
  socklen_t size = sizeof(endpoint);
  CHECK(getsockname(fd, (struct sockaddr *)&endpoint, &size) == 0);
  CHECK(size == sizeof(endpoint) && ntohs(endpoint.sin_port) >= 1024);
  CHECK(listen(fd, backlog) == 0);
  CHECK(option(fd, SO_ACCEPTCONN) == 1 && option(fd, SO_TYPE) == SOCK_STREAM);
  return fd;
}
static int client(int flags) {
  int fd = socket(AF_INET, SOCK_STREAM | flags, IPPROTO_TCP);
  CHECK(fd >= 0);
  return fd;
}
static void ready(int fd, short events, int timeout) {
  struct pollfd p = {fd, events, 0};
  CHECK(poll(&p, 1, timeout) == 1);
  CHECK(p.revents & events);
}
static int accept_ready(int fd, int flags) {
  ready(fd, POLLIN, 3000);
  struct sockaddr_in peer;
  socklen_t size = sizeof(peer);
  int accepted = accept4(fd, (struct sockaddr *)&peer, &size, flags);
  CHECK(accepted >= 0);
  CHECK(size == sizeof(peer) && peer.sin_family == AF_INET &&
        peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK) && peer.sin_port != 0);
  return accepted;
}
static void basic(void) {
  int l = listener(4), c = client(SOCK_CLOEXEC);
  CHECK(connect(c, (struct sockaddr *)&endpoint, sizeof(endpoint)) == 0);
  int s = accept_ready(l, SOCK_CLOEXEC), alias = dup(c);
  CHECK(alias >= 0);
  CHECK(fcntl(c, F_GETFD) == FD_CLOEXEC && fcntl(alias, F_GETFD) == 0);
  CHECK(fcntl(s, F_GETFD) == FD_CLOEXEC && !(fcntl(s, F_GETFL) & O_NONBLOCK));
  CHECK(fcntl(alias, F_SETFL, O_NONBLOCK) == 0 &&
        (fcntl(c, F_GETFL) & O_NONBLOCK));
  CHECK(fcntl(c, F_SETFL, 0) == 0 && !(fcntl(alias, F_GETFL) & O_NONBLOCK));
  struct stat st;
  CHECK(fstat(s, &st) == 0 && S_ISSOCK(st.st_mode));
  CHECK(st.st_uid == geteuid());
  CHECK(option(c, SO_TYPE) == SOCK_STREAM && option(s, SO_ACCEPTCONN) == 0 &&
        option(c, SO_ERROR) == 0);
  CHECK(close(l) == 0);
  CHECK(write(alias, "hello", 5) == 5);
  char bytes[16] = {0};
  CHECK(recv(s, bytes, 5, MSG_PEEK) == 5 && memcmp(bytes, "hello", 5) == 0);
  CHECK(recv(s, bytes, 5, MSG_WAITALL) == 5 && memcmp(bytes, "hello", 5) == 0);
  CHECK(recv(s, bytes, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
  CHECK(shutdown(c, SHUT_WR) == 0);
  CHECK(read(s, bytes, 1) == 0);
  CHECK(write(s, "reply", 5) == 5);
  CHECK(read(c, bytes, 5) == 5 && memcmp(bytes, "reply", 5) == 0);
  CHECK(close(c) == 0);
  CHECK(write(s, "x", 1) == 1);
  CHECK(read(alias, bytes, 1) == 1 && bytes[0] == 'x');
  CHECK(close(s) == 0 && close(alias) == 0);
  puts("inet-stream: PASS duplex, peek, half-close, description flags and "
       "native FD lifetime");
}
static void nonblocking(void) {
  int l = listener(1), first = client(0);
  CHECK(connect(first, (struct sockaddr *)&endpoint, sizeof(endpoint)) == 0);
  int second = client(SOCK_NONBLOCK);
  CHECK(connect(second, (struct sockaddr *)&endpoint, sizeof(endpoint)) == -1 &&
        errno == EINPROGRESS);
  CHECK(connect(second, (struct sockaddr *)&endpoint, sizeof(endpoint)) == -1 &&
        errno == EALREADY);
  struct pollfd p = {second, POLLOUT, 0};
  CHECK(poll(&p, 1, 50) == 0);
  int a = accept_ready(l, 0);
  ready(second, POLLOUT, 3000);
  CHECK(option(second, SO_ERROR) == 0);
  int b = accept_ready(l, SOCK_NONBLOCK);
  CHECK(fcntl(b, F_GETFL) & O_NONBLOCK);
  CHECK(write(second, "ready", 5) == 5);
  char bytes[5];
  ready(b, POLLIN, 1000);
  CHECK(read(b, bytes, 5) == 5 && memcmp(bytes, "ready", 5) == 0);
  CHECK(close(a) == 0 && close(b) == 0 && close(first) == 0 &&
        close(second) == 0 && close(l) == 0);
  puts(
      "inet-stream: PASS EINPROGRESS, EALREADY, backlog retry and poll wakeup");
}
static void timeout(void) {
  int l = listener(1), first = client(0);
  CHECK(connect(first, (struct sockaddr *)&endpoint, sizeof(endpoint)) == 0);
  int second = client(0);
  struct timeval t = {0, 100000};
  CHECK(setsockopt(second, SOL_SOCKET, SO_SNDTIMEO, &t, sizeof(t)) == 0);
  CHECK(connect(second, (struct sockaddr *)&endpoint, sizeof(endpoint)) == -1 &&
        errno == ETIMEDOUT);
  CHECK(option(second, SO_ERROR) == ETIMEDOUT && option(second, SO_ERROR) == 0);
  int a = accept_ready(l, 0);
  CHECK(close(a) == 0 && close(first) == 0 && close(second) == 0 &&
        close(l) == 0);
  puts("inet-stream: PASS blocking deadline abort and shared SO_ERROR "
       "consumption");
}
static _Atomic unsigned connecting;
static int cancelled_socket;
static void *pending_connect(void *unused) {
  (void)unused;
  CHECK(cookie == 17);
  atomic_store(&connecting, 1);
  int result =
      connect(cancelled_socket, (struct sockaddr *)&endpoint, sizeof(endpoint));
  fprintf(stderr, "inet-stream: unexpected connect result=%d errno=%d\n",
          result, errno);
  return NULL;
}
static void cancellation(void) {
  int l = listener(1), first = client(0);
  CHECK(connect(first, (struct sockaddr *)&endpoint, sizeof(endpoint)) == 0);
  cancelled_socket = client(0);
  pthread_t thread;
  CHECK(pthread_create(&thread, NULL, pending_connect, NULL) == 0);
  while (!atomic_load(&connecting))
    sched_yield();
  // The worker must have started the pending open before cancellation. A
  // fixed host delay can cancel at connect's entry cancellation point instead.
  struct pollfd pending = {cancelled_socket, POLLOUT, 0};
  for (;;) {
    int polled = poll(&pending, 1, 0);
    CHECK(polled >= 0);
    if (polled == 0)
      break;
    delay();
  }
  CHECK(pthread_cancel(thread) == 0);
  void *result = NULL;
  CHECK(pthread_join(thread, &result) == 0 && result == PTHREAD_CANCELED);
  // Native final-release notification is asynchronous. Wait for its observable
  // result; repeatedly seeing zero must never be accepted as successful
  // cleanup.
  int failure = 0;
  for (unsigned retry = 0; retry < 100 && failure == 0; ++retry) {
    failure = option(cancelled_socket, SO_ERROR);
    if (failure == 0)
      delay();
  }
  if (failure != ECANCELED)
    fprintf(stderr, "inet-stream: cancellation SO_ERROR=%d expected=%d\n",
            failure, ECANCELED);
  CHECK(failure == ECANCELED && option(cancelled_socket, SO_ERROR) == 0);
  int a = accept_ready(l, 0);
  CHECK(close(a) == 0 && close(first) == 0 && close(cancelled_socket) == 0 &&
        close(l) == 0);
  puts("inet-stream: PASS pthread cancellation retires only the pending open");
}
static void inheritance(void) {
  int l = listener(1), c = client(0);
  CHECK(connect(c, (struct sockaddr *)&endpoint, sizeof(endpoint)) == 0);
  int s = accept_ready(l, 0);
  pid_t pid = fork();
  CHECK(pid >= 0);
  if (pid == 0) {
    CHECK(close(l) == 0 && close(s) == 0);
    CHECK(write(c, "fork", 4) == 4);
    _exit(0);
  }
  CHECK(close(c) == 0);
  char bytes[4];
  CHECK(read(s, bytes, 4) == 4 && memcmp(bytes, "fork", 4) == 0);
  int status = -1;
  CHECK(waitpid(pid, &status, 0) == pid && status == 0);
  CHECK(close(l) == 0 && close(s) == 0);
  puts("inet-stream: PASS fork shares native open description");
  l = listener(1);
  c = client(SOCK_CLOEXEC);
  CHECK(connect(c, (struct sockaddr *)&endpoint, sizeof(endpoint)) == 0);
  s = accept_ready(l, 0);
  int alias = dup(c);
  CHECK(alias >= 0);
  char kept[16], closed[16];
  CHECK(snprintf(kept, sizeof(kept), "%d", alias) > 0 &&
        snprintf(closed, sizeof(closed), "%d", c) > 0);
  pid = fork();
  CHECK(pid >= 0);
  if (pid == 0) {
    CHECK(close(l) == 0 && close(s) == 0);
    char *args[] = {"different-argv0", "--inherited", kept, closed, NULL};
    execv("/system/bin/llvm-runtime-probe", args);
    _exit(126);
  }
  CHECK(close(alias) == 0 && close(c) == 0);
  CHECK(read(s, bytes, 4) == 4 && memcmp(bytes, "exec", 4) == 0);
  CHECK(waitpid(pid, &status, 0) == pid && status == 0);
  CHECK(close(l) == 0 && close(s) == 0);
  puts(
      "inet-stream: PASS exec Handle inheritance and descriptor-local CLOEXEC");
}
int main(int argc, char **argv) {
  CHECK(cookie == 17);
  if (argc == 4 && strcmp(argv[1], "--inherited") == 0) {
    int kept = atoi(argv[2]), closed = atoi(argv[3]);
    CHECK(fcntl(closed, F_GETFD) == -1 && errno == EBADF);
    CHECK(option(kept, SO_TYPE) == SOCK_STREAM && write(kept, "exec", 4) == 4);
    return 0;
  }
  CHECK(argc == 2);
  CHECK(geteuid() ==
        (unsigned)(strcmp(argv[1], "--expect-euid=501") == 0 ? 501 : 0));
  alarm(30);
  basic();
  nonblocking();
  timeout();
  cancellation();
  inheritance();
  printf("inet-stream: PASS native POSIX TCP euid=%u\n", (unsigned)geteuid());
  return 0;
}
