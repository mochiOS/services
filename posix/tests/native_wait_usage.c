#define _GNU_SOURCE 1
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "wait-usage: FAIL line=%d errno=%d: %s\n", __LINE__, errno, #x); \
  return 1; } } while (0)

int mochi_wait_usage_probe(void) {
  int gate[2];
  CHECK(pipe(gate) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    close(gate[1]);
    char byte;
    if (read(gate[0], &byte, 1) != 1) _exit(120);
    close(gate[0]);
    struct timespec start, now;
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start)) _exit(121);
    do {
      if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &now)) _exit(122);
    } while ((now.tv_sec - start.tv_sec) * 1000000000L + now.tv_nsec - start.tv_nsec < 20000000L);
    _exit(37);
  }
  CHECK(close(gate[0]) == 0);
  int status = 0x12345678;
  struct rusage usage, unchanged;
  memset(&usage, 0xa5, sizeof(usage));
  unchanged = usage;
  errno = 123;
  CHECK(wait4(child, &status, WNOHANG, &usage) == 0 && errno == 123);
  CHECK(status == 0x12345678 && !memcmp(&usage, &unchanged, sizeof(usage)));
  CHECK(write(gate[1], "x", 1) == 1 && close(gate[1]) == 0);
  CHECK(wait4(child, &status, 0, &usage) == child);
  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 37);
  CHECK(usage.ru_utime.tv_sec >= 0 && usage.ru_utime.tv_usec >= 0 && usage.ru_utime.tv_usec < 1000000);
  CHECK(usage.ru_stime.tv_sec >= 0 && usage.ru_stime.tv_usec >= 0 && usage.ru_stime.tv_usec < 1000000);
  CHECK(usage.ru_utime.tv_sec || usage.ru_utime.tv_usec || usage.ru_stime.tv_sec || usage.ru_stime.tv_usec);
  CHECK(wait4(child, NULL, 0, &usage) == -1 && errno == ECHILD);
  CHECK(wait4(-1, NULL, 0x40000000, &usage) == -1 && errno == EINVAL);
  child = fork();
  CHECK(child >= 0);
  if (child == 0) _exit(19);
  CHECK(wait3(&status, 0, &usage) == child && WIFEXITED(status) && WEXITSTATUS(status) == 19);
  child = fork();
  CHECK(child >= 0);
  if (child == 0) _exit(5);
  CHECK(wait(&status) == child && WIFEXITED(status) && WEXITSTATUS(status) == 5);
  child = fork();
  CHECK(child >= 0);
  if (child == 0) _exit(7);
  CHECK(wait4(child, &status, 0, NULL) == child && WIFEXITED(status) && WEXITSTATUS(status) == 7);
  puts("wait-usage: PASS selected child CPU nohang wait4 wait3 wait and optional usage");
  return 0;
}
