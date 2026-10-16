/* Caller output faults must never publish a hidden half of a socket pair. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned type, options, fault_case;
static volatile sig_atomic_t faulted;
static sigjmp_buf destination;
static int retry_kind;
static int *retry_output;
static int create_pair(int kind, int *output);
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr,                                                          \
              "socket-creation: FAIL type=%u options=%u fault=%u line=%u "     \
              "errno=%d: %s\n",                                                \
              type, options, fault_case, __LINE__, errno, #x);                 \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static int64_t native(uint64_t number, uint64_t a, uint64_t b, uint64_t c) {
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(a), "S"(b), "d"(c)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
static void fault_handler(int signal) {
  if (signal != SIGSEGV)
    _exit(91);
  faulted = 1;
  int64_t baseline = native(680, 0, 0, 0);
  if (create_pair(retry_kind, retry_output) != -1 || errno != EFAULT ||
      native(680, 0, 0, 0) != baseline)
    _exit(92);
  siglongjmp(destination, 37);
}
static int flags_match(int fd) {
  int status = fcntl(fd, F_GETFL), descriptor = fcntl(fd, F_GETFD);
  return status >= 0 && descriptor >= 0 &&
         !!(status & O_NONBLOCK) == !!options &&
         !!(descriptor & FD_CLOEXEC) == !!options;
}
static int create_pair(int kind, int *output) {
  if (type == 2)
    return pipe2(output, options ? O_NONBLOCK | O_CLOEXEC : 0);
  return socketpair(AF_UNIX, kind, 0, output);
}
int main(void) {
  struct sigaction action = {0};
  action.sa_handler = fault_handler;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  /* Datagram I/O lazily acquires one process-owned worker endpoint. Keep
   * that deliberate cache outside the per-operation leak baselines. */
  int warm_pair[2];
  char warm_byte = 0;
  CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, warm_pair) == 0);
  CHECK(write(warm_pair[0], "w", 1) == 1 &&
        read(warm_pair[1], &warm_byte, 1) == 1 && warm_byte == 'w');
  CHECK(close(warm_pair[0]) == 0 && close(warm_pair[1]) == 0);
  for (type = 0; type < 3; ++type) {
    for (options = 0; options < 2; ++options) {
      int kind = (type ? SOCK_DGRAM : SOCK_STREAM) |
                 (options ? SOCK_NONBLOCK | SOCK_CLOEXEC : 0);
      int64_t baseline = native(680, 0, 0, 0);
      int single = socket(AF_UNIX, kind, 0);
      CHECK(single >= 0 && flags_match(single));
      CHECK(close(single) == 0 && native(680, 0, 0, 0) == baseline);
      for (fault_case = 0; fault_case < 3; ++fault_case) {
        unsigned char *page = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(page != MAP_FAILED);
        int *output = (int *)(page + 4096 - sizeof(int));
        output[0] = output[1] = -123;
        if (fault_case)
          CHECK(mprotect(page + (fault_case == 2 ? 4096 : 0), 4096,
                         PROT_READ) == 0);
        faulted = 0;
        retry_kind = kind;
        retry_output = output;
        int jumped = sigsetjmp(destination, 1);
        if (!jumped) {
          int result = create_pair(kind, output);
          if (fault_case) {
            CHECK(result == -1 && errno == EFAULT);
            CHECK(native(680, 0, 0, 0) == baseline);
            *(volatile char *)(page + (fault_case == 2 ? 4096 : 0)) = 1;
            CHECK(0);
          }
          CHECK(result == 0);
          CHECK(output[0] == single && output[1] >= 0 &&
                output[0] != output[1]);
          CHECK(flags_match(output[0]) && flags_match(output[1]));
          if (type == 2) {
            CHECK((fcntl(output[0], F_GETFL) & O_ACCMODE) == O_RDONLY);
            CHECK((fcntl(output[1], F_GETFL) & O_ACCMODE) == O_WRONLY);
          }
          CHECK(write(output[type == 2 ? 1 : 0], "q", 1) == 1);
          char byte = 0;
          CHECK(read(output[type == 2 ? 0 : 1], &byte, 1) == 1 && byte == 'q');
          CHECK(close(output[0]) == 0 && close(output[1]) == 0);
        } else {
          CHECK(jumped == 37 && faulted && fault_case != 0);
          if (fault_case == 1)
            CHECK(output[0] == -123 && output[1] == -123);
          else {
            /* MemoryCopy may reject the entire range or copy a prefix.
             * Neither form may publish a descriptor on failure. */
            CHECK((output[0] == single || output[0] == -123) && output[1] == -123);
            CHECK(fcntl(single, F_GETFD) == -1 && errno == EBADF);
          }
        }
        CHECK(faulted == (fault_case != 0));
        CHECK(native(680, 0, 0, 0) == baseline);
        int reused = socket(AF_UNIX, kind, 0);
        CHECK(reused == single && close(reused) == 0);
        CHECK(munmap(page, 8192) == 0);
        fprintf(stderr, "socket-creation: type=%u options=%u fault=%u PASS\n",
                type, options, fault_case);
      }
    }
    /* One available FD cannot admit a pair, and failure leaves it free. */
    struct rlimit original, limited;
    CHECK(getrlimit(RLIMIT_NOFILE, &original) == 0);
    int next = socket(AF_UNIX, type ? SOCK_DGRAM : SOCK_STREAM, 0);
    CHECK(next >= 0 && close(next) == 0);
    limited = original;
    limited.rlim_cur = next + 1;
    CHECK(setrlimit(RLIMIT_NOFILE, &limited) == 0);
    int output[2] = {-123, -123};
    int64_t baseline = native(680, 0, 0, 0);
    CHECK(create_pair(type ? SOCK_DGRAM : SOCK_STREAM, output) == -1 &&
          errno == EMFILE && output[0] == -123 && output[1] == -123);
    CHECK(native(680, 0, 0, 0) == baseline);
    int single = socket(AF_UNIX, type ? SOCK_DGRAM : SOCK_STREAM, 0);
    CHECK(single == next && close(single) == 0);
    CHECK(setrlimit(RLIMIT_NOFILE, &original) == 0);
  }
  puts("socket-creation: PASS 18 socket/pipe publication/EFAULT cases with active handlers, 6 socket "
       "flag "
       "cases and 3 descriptor-limit cases; no hidden FDs or Handles");
  return 0;
}
