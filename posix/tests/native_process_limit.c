#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      printf("process-limit: FAIL line=%d errno=%d\n", __LINE__, errno);       \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static int64_t nproc_handles(void) {
  uint64_t number = 680;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(0), "S"(0)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}

static int nproc_isolated(void) {
  /* No other test process uses this real UID. Native capabilities are
   * unchanged; POSIX credentials and limits are private to this child. */
  CHECK(setuid(54137) == 0 && getuid() == 54137);
  struct rlimit bound;
  CHECK(getrlimit(RLIMIT_NPROC, &bound) == 0);
  int64_t handles = nproc_handles();
  CHECK(handles > 0);
  for (rlim_t soft = 0; soft <= 1; ++soft) {
    bound.rlim_cur = soft;
    CHECK(setrlimit(RLIMIT_NPROC, &bound) == 0);
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
      errno = 0;
      pid_t child = fork();
      if (child == 0)
        _exit(88);
      CHECK(child == -1 && errno == EAGAIN);
      pid_t output = 12345;
      char *arguments[] = {"compositor.service", NULL};
      char *environment[] = {NULL};
      errno = EDOM;
      CHECK(posix_spawn(&output, "/system/services/compositor.service", NULL,
                        NULL, arguments, environment) == EAGAIN);
      CHECK(output == 12345 && errno == EDOM);
      CHECK(nproc_handles() == handles);
    }
  }
  errno = 0;
  CHECK(waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD);
  bound.rlim_cur = 2;
  CHECK(setrlimit(RLIMIT_NPROC, &bound) == 0);
  int ready[2], release[2];
  CHECK(pipe(ready) == 0 && pipe(release) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    close(ready[0]);
    close(release[1]);
    errno = 0;
    pid_t grandchild = fork();
    if (grandchild == 0)
      _exit(89);
    char result = grandchild == -1 && errno == EAGAIN ? 'Y' : 'N';
    if (write(ready[1], &result, 1) != 1)
      _exit(90);
    char byte;
    if (read(release[0], &byte, 1) != 1)
      _exit(91);
    _exit(result == 'Y' ? 19 : 92);
  }
  CHECK(close(ready[1]) == 0 && close(release[0]) == 0);
  char byte;
  CHECK(read(ready[0], &byte, 1) == 1 && byte == 'Y');
  errno = 0;
  pid_t denied = fork();
  if (denied == 0)
    _exit(93);
  CHECK(denied == -1 && errno == EAGAIN);
  CHECK(write(release[1], "X", 1) == 1);
  CHECK(close(ready[0]) == 0 && close(release[1]) == 0);
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 19);
  /* Reaping releases the slot. The next fork must succeed at the same limit. */
  child = fork();
  CHECK(child >= 0);
  if (child == 0)
    _exit(20);
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 20);
  CHECK(nproc_handles() == handles);
  return 0;
}

int main(void) {
  struct rlimit original, after;
  uid_t original_uid = getuid();
  CHECK(getrlimit(RLIMIT_NPROC, &original) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0)
    _exit(nproc_isolated());
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  CHECK(getuid() == original_uid && getrlimit(RLIMIT_NPROC, &after) == 0);
  CHECK(after.rlim_cur == original.rlim_cur &&
        after.rlim_max == original.rlim_max);
  puts(
      "process-limit: PASS fork/spawn EAGAIN, pid/errno and Handles preserved, "
      "real-UID child accounting and wait releases slot; parent unchanged");
  return 0;
}
