#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
static unsigned kind;
static int auxiliary;
static char path[96], shared_name[96];
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "fcntl-status: FAIL kind=%u line=%u errno=%d: %s\n",     \
              kind, __LINE__, errno, #x);                                      \
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
static int create(void) {
  auxiliary = -1;
  if (kind == 0)
    return open(path, O_CREAT | O_RDWR | O_APPEND, 0600);
  if (kind == 1)
    return open("/tmp", O_RDONLY | O_DIRECTORY);
  if (kind == 8)
    return open("/dev/null", O_RDWR | O_APPEND);
  int pair[2];
  if (kind == 2 || kind == 3) {
    if (pipe(pair))
      return -1;
    auxiliary = pair[kind == 2 ? 1 : 0];
    return pair[kind == 2 ? 0 : 1];
  }
  if (kind == 4 || kind == 5) {
    if (socketpair(AF_UNIX, kind == 4 ? SOCK_STREAM : SOCK_DGRAM, 0, pair))
      return -1;
    auxiliary = pair[1];
    return pair[0];
  }
  if (kind == 6) {
    int fd = shm_open(shared_name, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd >= 0 && shm_unlink(shared_name)) {
      close(fd);
      return -1;
    }
    return fd;
  }
  if (openpty(&auxiliary, &pair[1], NULL, NULL, NULL))
    return -1;
  return pair[1];
}
int main(void) {
  snprintf(path, sizeof(path), "/tmp/fcntl-status-%d", (int)getpid());
  snprintf(shared_name, sizeof(shared_name), "/fcntl-status-%d", (int)getpid());
  CHECK(unlink(path) == 0 || errno == ENOENT);
  CHECK(shm_unlink(shared_name) == 0 || errno == ENOENT);
  for (kind = 0; kind < 9; ++kind) {
    int fd = create();
    CHECK(fd >= 0);
    int alias = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    CHECK(alias >= 0 && fcntl(alias, F_GETFD) == FD_CLOEXEC);
    int descriptor_flags = fcntl(fd, F_GETFD);
    int original = fcntl(fd, F_GETFL);
    CHECK(original >= 0);
    int access = original & O_ACCMODE;
    int persistent = kind == 0 || kind == 6 || kind == 8 ? O_APPEND : 0;
    CHECK(fcntl(fd, F_SETFL, access | persistent) == 0);
    int64_t baseline = native_count();
    CHECK(baseline > 0);
    for (unsigned iteration = 0; iteration < 12; ++iteration) {
      int flags = access | persistent | (iteration & 1 ? O_NONBLOCK : 0);
      CHECK(fcntl(iteration & 2 ? alias : fd, F_SETFL, flags) == 0);
      CHECK(fcntl(alias, F_GETFL) == flags && fcntl(fd, F_GETFL) == flags);
      int enabled = iteration & 1 ? 0 : -1;
      CHECK(ioctl(iteration & 2 ? fd : alias, FIONBIO, &enabled) == 0);
      int changed = access | persistent | (enabled ? O_NONBLOCK : 0);
      CHECK(fcntl(alias, F_GETFL) == changed && fcntl(fd, F_GETFL) == changed);
      CHECK(fcntl(alias, F_GETFD) == FD_CLOEXEC &&
            fcntl(fd, F_GETFD) == descriptor_flags);
      CHECK(native_count() == baseline);
    }
    CHECK(close(alias) == 0 && close(fd) == 0);
    if (auxiliary >= 0)
      CHECK(close(auxiliary) == 0);
    CHECK(native_count() == baseline - 2 - (auxiliary >= 0));
    fprintf(stderr, "fcntl-status: kind=%u PASS\n", kind);
  }
  CHECK(unlink(path) == 0);
  puts("fcntl-status: PASS 9 description kinds, 108 fcntl and 108 FIONBIO "
       "updates, "
       "descriptor-local CLOEXEC and reference recovery");
  return 0;
}
