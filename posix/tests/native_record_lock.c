#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "libc-lock: FAIL line=%d errno=%d: %s\n", __LINE__,      \
              errno, #x);                                                      \
      return 1;                                                                \
    }                                                                          \
  } while (0)
_Static_assert(sizeof(struct flock) == 32, "flock ABI size");
_Static_assert(offsetof(struct flock, l_pid) == 24 &&
                   sizeof(((struct flock *)0)->l_pid) == 4,
               "flock PID ABI");
static const char *paths[] = {"/tmp/libc-lock-a-158", "/tmp/libc-lock-b-158"};

static int set(int fd, short type) {
  struct flock value = {
      .l_type = type, .l_whence = SEEK_SET, .l_start = 10, .l_len = 20};
  return fcntl(fd, F_SETLK, &value);
}
static int query(int fd, pid_t owner) {
  struct flock value = {.l_type = F_WRLCK,
                        .l_whence = SEEK_SET,
                        .l_start = 0,
                        .l_len = 0,
                        .l_pid = 0x12345678};
  CHECK(fcntl(fd, F_GETLK, &value) == 0);
  if (owner) {
    CHECK(value.l_type == F_WRLCK && value.l_whence == SEEK_SET &&
          value.l_start == 10 && value.l_len == 20 && value.l_pid == owner);
  } else {
    CHECK(value.l_type == F_UNLCK && value.l_start == 0 && value.l_len == 0 &&
          value.l_pid == 0x12345678);
  }
  return 0;
}
static int foreign_query(int fd, pid_t owner) {
  pid_t child = fork();
  CHECK(child >= 0);
  if (!child)
    _exit(query(fd, owner));
  int status;
  CHECK(waitpid(child, &status, 0) == child && status == 0);
  return 0;
}

static int after_exec(int argc, char **argv) {
  if (argc != 7 || strcmp(argv[1], "--libc-lock-exec"))
    return -1;
  int output = atoi(argv[2]), input = atoi(argv[3]), closed = atoi(argv[4]),
      retained = atoi(argv[5]), alias = atoi(argv[6]);
  CHECK(fcntl(closed, F_GETFD) == -1 && errno == EBADF);
  CHECK(fcntl(retained, F_GETFD) >= 0 && fcntl(alias, F_GETFD) >= 0);
  CHECK(close(alias) == 0);
  CHECK(write(output, "E", 1) == 1);
  char byte;
  CHECK(read(input, &byte, 1) == 1);
  CHECK(close(retained) == 0);
  CHECK(write(output, "C", 1) == 1);
  CHECK(read(input, &byte, 1) == 1);
  return 0;
}

static int exec_case(int a, int b, int fail) {
  int ready[2], go[2];
  CHECK(pipe(ready) == 0 && pipe(go) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (!child) {
    CHECK(close(ready[0]) == 0 && close(go[1]) == 0);
    CHECK(set(a, F_WRLCK) == 0 && set(b, F_WRLCK) == 0);
    int alias = dup(a);
    CHECK(alias >= 0);
    CHECK(fcntl(a, F_SETFD, FD_CLOEXEC) == 0);
    // More than one IPC batch, all selected through actual CLOEXEC flags.
    for (int i = 0; i < 5; i++) {
      int fd = dup(a);
      CHECK(fd >= 0 && fcntl(fd, F_SETFD, FD_CLOEXEC) == 0);
    }
    char output[16], input[16], closed[16], retained[16], kept[16];
    snprintf(output, sizeof(output), "%d", ready[1]);
    snprintf(input, sizeof(input), "%d", go[0]);
    snprintf(closed, sizeof(closed), "%d", a);
    snprintf(retained, sizeof(retained), "%d", b);
    snprintf(kept, sizeof(kept), "%d", alias);
    char *arguments[] = {"libc-lock", "--libc-lock-exec", output, input,
                         closed,      retained,           kept,   NULL};
    if (fail) {
      struct rlimit old, limit;
      CHECK(getrlimit(RLIMIT_AS, &old) == 0);
      limit = old;
      limit.rlim_cur = 0;
      CHECK(setrlimit(RLIMIT_AS, &limit) == 0);
      errno = 0;
      int result = execv("/system/services/compositor.service", arguments),
          error = errno;
      CHECK(setrlimit(RLIMIT_AS, &old) == 0);
      CHECK(result == -1 && error == ENOMEM && fcntl(a, F_GETFD) == FD_CLOEXEC);
      CHECK(write(ready[1], "F", 1) == 1);
      char byte;
      CHECK(read(go[0], &byte, 1) == 1);
      CHECK(close(a) == 0);
      CHECK(write(ready[1], "C", 1) == 1 && read(go[0], &byte, 1) == 1);
      _exit(0);
    }
    execv("/system/services/compositor.service", arguments);
    fprintf(stderr, "libc-lock: exec failed errno=%d\n", errno);
    _exit(1);
  }
  CHECK(close(ready[1]) == 0 && close(go[0]) == 0);
  char byte;
  CHECK(read(ready[0], &byte, 1) == 1 && byte == (fail ? 'F' : 'E'));
  CHECK(query(a, fail ? child : 0) == 0 && query(b, child) == 0);
  CHECK(write(go[1], "G", 1) == 1 && read(ready[0], &byte, 1) == 1 &&
        byte == 'C');
  CHECK(query(a, 0) == 0 && query(b, fail ? child : 0) == 0);
  CHECK(write(go[1], "G", 1) == 1);
  int status;
  CHECK(waitpid(child, &status, 0) == child && status == 0);
  CHECK(query(a, 0) == 0 && query(b, 0) == 0);
  CHECK(close(ready[0]) == 0 && close(go[1]) == 0);
  fprintf(
      stderr, "libc-lock: PASS %s\n",
      fail ? "failed exec cancels preparation and preserves FD flags and locks"
           : "automatic batched CLOEXEC release and inherited lock "
             "notification state");
  return 0;
}

int main(int argc, char **argv) {
  int mode = after_exec(argc, argv);
  if (mode >= 0)
    return mode;
  unlink(paths[0]);
  unlink(paths[1]);
  int a = open(paths[0], O_CREAT | O_EXCL | O_RDWR, 0600),
      b = open(paths[1], O_CREAT | O_EXCL | O_RDWR, 0600);
  CHECK(a >= 0 && b >= 0 && write(a, "abcdef", 6) == 6);
  struct flock value = {
      .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 10, .l_len = 20};
  CHECK((uintptr_t)&value > UINT32_MAX);
  CHECK(fcntl(a, F_GETFD) == 0);
  CHECK(fcntl(a, F_DUPFD, -1) == -1 && errno == EINVAL);
  CHECK(fcntl(a, F_SETLK, NULL) == -1 && errno == EFAULT);
  CHECK(fcntl(a, F_GETLK, NULL) == -1 && errno == EFAULT);
  CHECK(fcntl(-1, F_SETLK, &value) == -1 && errno == EBADF);
  CHECK(fcntl(a, F_SETLK, &value) == 0 && query(a, 0) == 0);
  CHECK(foreign_query(a, getpid()) == 0);
  int readonly = open(paths[0], O_RDONLY), writeonly = open(paths[0], O_WRONLY);
  CHECK(readonly >= 0 && writeonly >= 0);
  CHECK(set(readonly, F_WRLCK) == -1 && errno == EBADF);
  CHECK(set(writeonly, F_RDLCK) == -1 && errno == EBADF);
  CHECK(close(readonly) == 0 && foreign_query(a, 0) == 0 &&
        close(writeonly) == 0);
  void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(page != MAP_FAILED);
  memcpy(page, &value, sizeof(value));
  CHECK(mprotect(page, 4096, PROT_READ) == 0);
  CHECK(fcntl(a, F_SETLK, page) == 0);
  CHECK(fcntl(a, F_GETLK, page) == -1 && errno == EFAULT);
  CHECK(munmap(page, 4096) == 0);
  int duplicate = dup(a);
  CHECK(duplicate >= 0 && close(duplicate) == 0 && foreign_query(a, 0) == 0);
  fprintf(stderr, "libc-lock: PASS variadic pointers, checked flock memory, "
                  "access modes and any-description close\n");

  CHECK(set(a, F_WRLCK) == 0);
  CHECK(dup2(-1, a) == -1 && errno == EBADF && foreign_query(a, getpid()) == 0);
  CHECK(dup2(a, a) == a && foreign_query(a, getpid()) == 0);
  duplicate = dup(a);
  CHECK(duplicate >= 0 && dup2(duplicate, a) == a && foreign_query(a, 0) == 0);
  CHECK(close(duplicate) == 0 && set(a, F_WRLCK) == 0);
  int alias = dup(a);
  CHECK(alias >= 0 && dup2(b, a) == a);
  CHECK(foreign_query(alias, 0) == 0 && close(alias) == 0 && close(a) == 0);
  a = open(paths[0], O_RDWR);
  CHECK(a >= 0);
  fprintf(stderr, "libc-lock: PASS dup2 replacement releases locks, same-fd "
                  "and failed duplicate preserve them\n");
  CHECK(exec_case(a, b, 0) == 0 && exec_case(a, b, 1) == 0);
  CHECK(close(a) == 0 && close(b) == 0 && unlink(paths[0]) == 0 &&
        unlink(paths[1]) == 0);
  return 0;
}
