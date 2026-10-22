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

extern int ptsname_r(int, char *, size_t);
extern int tcgetwinsize(int, struct winsize *);

static unsigned mode;
static volatile sig_atomic_t faulted;
static sigjmp_buf destination;
static int *retry_master, *retry_slave;
static struct termios *retry_attributes;
static struct winsize *retry_window;
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
  int64_t baseline = native(680, 0, 0, 0);
  if (openpty(retry_master, retry_slave, NULL, retry_attributes, retry_window) != -1 ||
      errno != EFAULT || native(680, 0, 0, 0) != baseline)
    _exit(92);
  siglongjmp(destination, 37);
}
int main(void) {
  int warm_master, warm_slave;
  struct termios raw;
  CHECK(openpty(&warm_master, &warm_slave, NULL, NULL, NULL) == 0);
  char name[64], short_name[1] = {'x'};
  CHECK(ptsname_r(warm_master, name, sizeof(name)) == 0);
  CHECK(strncmp(name, "/dev/pts/", 9) == 0);
  CHECK(ptsname_r(warm_master, short_name, sizeof(short_name)) == ERANGE);
  CHECK(short_name[0] == 'x');
  CHECK(ptsname_r(warm_slave, name, sizeof(name)) == ENOTTY);
  CHECK(ptsname_r(warm_master, name, sizeof(name)) == 0);
  int reopened = open(name, O_RDWR | O_NOCTTY);
  CHECK(reopened >= 0 && isatty(reopened) == 1);
  CHECK(close(reopened) == 0);
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
    retry_master = master;
    retry_slave = slave;
    retry_attributes = attributes;
    retry_window = window;
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
        CHECK(result == -1 &&
              errno == (mode < 6 ? EFAULT : mode == 6 ? ENOTSUP : EMFILE));
        CHECK(*master == (mode == 3 ? expected[0] : -123) && *slave == -123);
        CHECK(native(680, 0, 0, 0) == baseline);
        if (mode < 6) {
          unsigned offset = mode == 2 ? 0 : mode == 3 ? 4096 :
                            mode == 4 ? 8192 : 12288;
          *(volatile char *)(page + offset) = 1;
          CHECK(0);
        }
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
  puts("pty-creation: PASS 8 configuration, EFAULT input/output and FD-limit "
       "cases including active handlers; both references and reservations reclaimed");
  return 0;
}
