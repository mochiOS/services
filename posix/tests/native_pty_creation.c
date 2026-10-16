/* Real native PTY creation: configure before publication, including faults. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <termios.h>
#include <unistd.h>

static unsigned mode;
static volatile sig_atomic_t faulted;
static sigjmp_buf destination;
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "pty-creation: FAIL mode=%u line=%u errno=%d: %s\n",     \
              mode, __LINE__, errno, #x);                                      \
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
  siglongjmp(destination, 37);
}
int main(void) {
  int warm_master, warm_slave;
  struct termios raw;
  CHECK(openpty(&warm_master, &warm_slave, NULL, NULL, NULL) == 0);
  CHECK(tcgetattr(warm_slave, &raw) == 0);
  raw.c_lflag &= ~(ICANON | ECHO | ISIG);
  raw.c_oflag &= ~OPOST;
  raw.c_cc[VMIN] = 1;
  raw.c_cc[VTIME] = 0;
  CHECK(close(warm_master) == 0 && close(warm_slave) == 0);
  struct sigaction action = {0};
  action.sa_handler = fault_handler;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  for (mode = 0; mode < 8; ++mode) {
    unsigned char *page = mmap(NULL, 16384, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(page != MAP_FAILED);
    int *master = (int *)page, *slave = (int *)(page + 4096);
    struct termios *attributes = (struct termios *)(page + 8192);
    struct winsize *window = (struct winsize *)(page + 12288);
    *master = *slave = -123;
    *attributes = raw;
    *window = (struct winsize){40, 120, 1280, 800};
    int expected[2];
    CHECK(pipe(expected) == 0 && close(expected[0]) == 0 &&
          close(expected[1]) == 0);
    struct rlimit original, limited;
    CHECK(getrlimit(RLIMIT_NOFILE, &original) == 0);
    if (mode == 7) {
      limited = original;
      limited.rlim_cur = expected[0] + 1;
      CHECK(setrlimit(RLIMIT_NOFILE, &limited) == 0);
    }
    int64_t baseline = native(680, 0, 0, 0);
    if (mode == 2 || mode == 3)
      CHECK(mprotect(page + (mode == 2 ? 0 : 4096), 4096, PROT_READ) == 0);
    if (mode == 4 || mode == 5)
      CHECK(mprotect(page + (mode == 4 ? 8192 : 12288), 4096, PROT_NONE) == 0);
    if (mode == 6)
      attributes->c_lflag |= UINT32_C(0x80000000);
    faulted = 0;
    int jumped = sigsetjmp(destination, 1);
    if (!jumped) {
      int result = openpty(master, slave, NULL, mode == 1 ? NULL : attributes,
                           mode == 1 ? NULL : window);
      if (mode < 2) {
        CHECK(result == 0 && *master == expected[0] && *slave == expected[1]);
        if (mode == 0) {
          struct termios actual;
          struct winsize size;
          CHECK(tcgetattr(*slave, &actual) == 0 &&
                actual.c_lflag == raw.c_lflag &&
                actual.c_oflag == raw.c_oflag && actual.c_cc[VMIN] == 1);
          CHECK(tcgetwinsize(*master, &size) == 0 &&
                memcmp(&size, window, sizeof(size)) == 0);
          CHECK(tcgetwinsize(*slave, &size) == 0 &&
                memcmp(&size, window, sizeof(size)) == 0);
        }
        CHECK(write(*slave, "q", 1) == 1);
        char byte = 0;
        CHECK(read(*master, &byte, 1) == 1 && byte == 'q');
        CHECK(close(*master) == 0 && close(*slave) == 0);
      } else {
        CHECK(result == -1 && errno == (mode == 6 ? ENOTSUP : EMFILE));
        CHECK(*master == -123 && *slave == -123);
      }
    } else {
      CHECK(jumped == 37 && faulted && mode >= 2 && mode <= 5);
      if (mode == 3) {
        CHECK(*master == expected[0] && *slave == -123);
        CHECK(fcntl(*master, F_GETFD) == -1 && errno == EBADF);
      }
    }
    CHECK(faulted == (mode >= 2 && mode <= 5));
    CHECK(native(680, 0, 0, 0) == baseline);
    if (mode == 7)
      CHECK(setrlimit(RLIMIT_NOFILE, &original) == 0);
    int reused[2];
    CHECK(pipe(reused) == 0 && reused[0] == expected[0] &&
          reused[1] == expected[1]);
    CHECK(close(reused[0]) == 0 && close(reused[1]) == 0);
    CHECK(munmap(page, 16384) == 0);
    CHECK(native(680, 0, 0, 0) == baseline);
    fprintf(stderr, "pty-creation: mode=%u PASS\n", mode);
  }
  puts("pty-creation: PASS 8 configuration, input/output fault and FD-limit "
       "cases; "
       "both references and reservations reclaimed");
  return 0;
}
