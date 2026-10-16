/* Real socket controls: user-memory faults must not strand FD lifetime pins. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
static unsigned kind, mode;
static int operation_fd;
static volatile sig_atomic_t faulted;
static sigjmp_buf destination;
static void *caller_value;
static socklen_t *caller_length;
static int caller_copy(void) {
  if (mode == 1)
    return setsockopt(operation_fd, SOL_SOCKET, SO_SNDBUF, caller_value, sizeof(int));
  if (mode == 2)
    return setsockopt(operation_fd, SOL_SOCKET, SO_RCVTIMEO, caller_value, sizeof(struct timeval));
  if (mode == 3)
    return bind(operation_fd, caller_value, sizeof(struct sockaddr_un));
  if (mode == 16)
    return connect(operation_fd, caller_value, sizeof(struct sockaddr_un));
  if (mode < 7)
    return getsockopt(operation_fd, SOL_SOCKET, SO_TYPE, caller_value, caller_length);
  if (mode < 10)
    return getsockopt(operation_fd, SOL_SOCKET, SO_RCVTIMEO, caller_value, caller_length);
  if (mode < 13)
    return getsockname(operation_fd, caller_value, caller_length);
  return getpeername(operation_fd, caller_value, caller_length);
}
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr,                                                          \
              "socket-control-resources: FAIL kind=%u mode=%u line=%u "        \
              "errno=%d: %s\n",                                                \
              kind, mode, __LINE__, errno, #x);                                \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static int64_t native_count(void) {
  uint64_t number = 680;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"((uint64_t)0), "S"((uint64_t)0), "d"((uint64_t)0)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
static void failed_copy(int signal) {
  if (signal != SIGSEGV)
    _exit(91);
  if (caller_copy() != -1 || errno != EFAULT)
    _exit(93);
  if (close(operation_fd))
    _exit(92);
  faulted = 1;
  siglongjmp(destination, 37);
}
static int normal_controls(void) {
  int value = 4096;
  CHECK(setsockopt(operation_fd, SOL_SOCKET, SO_SNDBUF, &value,
                   sizeof(value)) == 0);
  socklen_t length = sizeof(value);
  CHECK(getsockopt(operation_fd, SOL_SOCKET, SO_TYPE, &value, &length) == 0);
  CHECK(value == (kind ? SOCK_DGRAM : SOCK_STREAM) && length == sizeof(value));
  length = 0;
  CHECK(getsockopt(operation_fd, SOL_SOCKET, SO_TYPE, NULL, &length) == 0 && length == 0);
  unsigned char truncated[3] = {0xa5, 0xa5, 0xa5};
  length = 1;
  CHECK(getsockopt(operation_fd, SOL_SOCKET, SO_TYPE, truncated + 1, &length) == 0);
  CHECK(length == 1 && truncated[0] == 0xa5 && truncated[2] == 0xa5 &&
        truncated[1] == *(unsigned char *)&value);
  struct timeval timeout = {0, 123000}, actual = {0};
  CHECK(setsockopt(operation_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) == 0);
  length = sizeof(actual);
  CHECK(getsockopt(operation_fd, SOL_SOCKET, SO_RCVTIMEO, &actual, &length) ==
        0);
  CHECK(length == sizeof(actual) && actual.tv_sec == 0 &&
        actual.tv_usec == 123000);
  struct sockaddr_un address;
  length = sizeof(address);
  CHECK(getsockname(operation_fd, (struct sockaddr *)&address, &length) == 0);
  CHECK(address.sun_family == AF_UNIX);
  length = sizeof(address);
  CHECK(getpeername(operation_fd, (struct sockaddr *)&address, &length) == 0);
  CHECK(address.sun_family == AF_UNIX);
  return 0;
}
int main(void) {
  struct sigaction action = {0};
  action.sa_handler = failed_copy;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  for (kind = 0; kind < 2; ++kind) {
    int pair[2];
    CHECK(socketpair(AF_UNIX, kind ? SOCK_DGRAM : SOCK_STREAM, 0, pair) == 0);
    operation_fd = pair[0];
    if (normal_controls())
      return 1;
    CHECK(shutdown(operation_fd, SHUT_WR) == 0);
    CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
    for (mode = 0; mode < 17; ++mode) {
      int64_t baseline = native_count();
      CHECK(socketpair(AF_UNIX, kind ? SOCK_DGRAM : SOCK_STREAM, 0, pair) == 0);
      operation_fd = pair[0];
      unsigned char *page = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      CHECK(page != MAP_FAILED);
      void *value = page;
      socklen_t *length = (socklen_t *)(page + 4096);
      *length = 128;
      if ((mode >= 1 && mode <= 3) || mode == 16)
        CHECK(mprotect(page, 4096, PROT_NONE) == 0);
      if (mode >= 4 && mode < 16) {
        unsigned stage = (mode - 4) % 3;
        if (stage == 0)
          CHECK(mprotect(page, 4096, PROT_READ) == 0);
        else
          CHECK(mprotect(page + 4096, 4096,
                         stage == 1 ? PROT_READ : PROT_NONE) == 0);
      }
      faulted = 0;
      caller_value = value;
      caller_length = length;
      int jumped = sigsetjmp(destination, 1);
      if (!jumped) {
        if (mode == 0) {
          if (normal_controls())
            return 1;
        } else {
          CHECK(caller_copy() == -1 && errno == EFAULT);
          CHECK(fcntl(operation_fd, F_GETFD) >= 0);
          void *trap = mode <= 3 || mode == 16 || (mode - 4) % 3 == 0
                           ? value : (void *)length;
          *(volatile char *)trap = 1;
          CHECK(0);
        }
        CHECK(mode == 0 && !faulted && close(operation_fd) == 0);
      } else {
        CHECK(jumped == 37 && mode != 0 && faulted);
        CHECK(fcntl(operation_fd, F_GETFD) == -1 && errno == EBADF);
      }
      CHECK(munmap(page, 8192) == 0 && close(pair[1]) == 0);
      CHECK(native_count() == baseline);
      fprintf(stderr, "socket-control-resources: kind=%u mode=%u PASS\n", kind,
              mode);
    }
  }
  puts("socket-control-resources: PASS 34 normal/input/output EFAULT cases including active handlers; no "
       "retained FD references");
  return 0;
}
