#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern int __mochios_fd_set_nonblocking(int, int);
extern int mochi_fd_from_file_handle(uint32_t, int);
struct handle_info {
  uint32_t handle, reserved;
  uint64_t rights;
};
static struct handle_info before[256], after[256];
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "description-flags: FAIL line=%u errno=%d: %s\n",        \
              __LINE__, errno, #x);                                            \
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
static int count(struct handle_info *items) {
  return (int)native(680, (uintptr_t)items, 256, 0);
}

int main(void) {
  alarm(60);
  const char *path = "/tmp/native-description-flags-163";
  unlink(path);
  int warm = open(path, O_CREAT | O_RDWR, 0600);
  CHECK(warm >= 0 && close(warm) == 0);
  int baseline = count(before);
  CHECK(baseline > 0 && baseline < 256);
  int fd = open(path, O_RDWR | O_CLOEXEC);
  CHECK(fd >= 0);
  int total = count(after);
  CHECK(total == baseline + 1);
  uint32_t source = 0;
  for (int i = 0; i < total; i++) {
    int found = 0;
    for (int j = 0; j < baseline; j++)
      found |= after[i].handle == before[j].handle;
    if (!found) {
      CHECK(source == 0);
      source = after[i].handle;
    }
  }
  CHECK(source != 0);
  int alias = dup(fd), independent = open(path, O_RDONLY);
  CHECK(alias >= 0 && independent >= 0);
  CHECK(write(fd, "abc", 3) == 3 && lseek(fd, 1, SEEK_SET) == 1);
  errno = 123;
  CHECK(fcntl(fd, F_SETFL, O_APPEND | O_NONBLOCK) == 0 && errno == 123);
  CHECK((fcntl(alias, F_GETFL) & (O_ACCMODE | O_APPEND | O_NONBLOCK)) ==
        (O_RDWR | O_APPEND | O_NONBLOCK));
  CHECK((fcntl(independent, F_GETFL) & (O_APPEND | O_NONBLOCK)) == 0);
  CHECK(fcntl(fd, F_GETFD) == FD_CLOEXEC && fcntl(alias, F_GETFD) == 0);
  CHECK(lseek(alias, 0, SEEK_CUR) == 1);
  CHECK(__mochios_fd_set_nonblocking(alias, 0) == 0 &&
        (fcntl(fd, F_GETFL) & O_APPEND));
  CHECK((fcntl(fd, F_GETFL) & O_NONBLOCK) == 0);
  CHECK(write(alias, "d", 1) == 1);
  char data[4];
  CHECK(pread(independent, data, 4, 0) == 4 && !memcmp(data, "abcd", 4));
  fprintf(stderr, "description-flags: PASS alias state, independent opens, "
                  "atomic masks and append writes\n");

  // READ|DUPLICATE|TRANSFER, deliberately no CONTROL or WRITE.
  int64_t narrowed = native(627, source, 1ULL | (1ULL << 62) | (1ULL << 63), 0);
  CHECK(narrowed > 0);
  int reduced = mochi_fd_from_file_handle((uint32_t)narrowed, O_CLOEXEC);
  CHECK(reduced >= 0 && native(626, (uint64_t)narrowed, 0, 0) == 0);
  CHECK((fcntl(reduced, F_GETFL) & O_APPEND) != 0);
  CHECK(fcntl(reduced, F_SETFL, 0) == -1 && errno == EACCES);
  CHECK(__mochios_fd_set_nonblocking(reduced, 1) == -1 && errno == EACCES);
  CHECK((fcntl(fd, F_GETFL) & (O_APPEND | O_NONBLOCK)) == O_APPEND);
  CHECK(close(reduced) == 0);
  fprintf(
      stderr,
      "description-flags: PASS attenuated READ query and CONTROL rejection\n");

  int writeonly = open(path, O_WRONLY),
      directory = open("/tmp", O_RDONLY | O_DIRECTORY);
  CHECK(writeonly >= 0 && directory >= 0);
  CHECK((fcntl(writeonly, F_GETFL) & O_ACCMODE) == O_WRONLY);
  CHECK(fcntl(writeonly, F_SETFL, O_NONBLOCK) == 0);
  CHECK((fcntl(writeonly, F_GETFL) & (O_ACCMODE | O_NONBLOCK)) ==
        (O_WRONLY | O_NONBLOCK));
  CHECK(fcntl(directory, F_SETFL, O_NONBLOCK) == 0 &&
        (fcntl(directory, F_GETFL) & O_NONBLOCK));
  CHECK(close(writeonly) == 0 && close(directory) == 0);
  fprintf(stderr, "description-flags: PASS write-only observation and "
                  "directory controls\n");

  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0)
    _exit(fcntl(alias, F_SETFL, O_NONBLOCK) == 0 ? 0 : 37);
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  CHECK((fcntl(fd, F_GETFL) & (O_APPEND | O_NONBLOCK)) == O_NONBLOCK);
  CHECK(close(alias) == 0 && close(independent) == 0 && close(fd) == 0 &&
        unlink(path) == 0);
  CHECK(count(after) == baseline);
  fprintf(stderr, "description-flags: PASS fork sharing and Handle cleanup\n");
  return 0;
}
