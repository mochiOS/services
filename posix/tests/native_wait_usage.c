#define _GNU_SOURCE 1
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <stddef.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "wait-usage: FAIL line=%d errno=%d: %s\n", __LINE__, errno, #x); \
  return 1; } } while (0)

_Static_assert(sizeof(struct rusage) == 40, "rusage ABI");
_Static_assert(offsetof(struct rusage, ru_maxrss) == 32, "rusage peak offset");

static int peak_usage(void) {
  struct rusage before, during, after, children;
  CHECK(getrusage(RUSAGE_SELF, &before) == 0 && before.ru_maxrss > 0);
  const size_t bytes = 8 * 1024 * 1024;
  volatile char *pages = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(pages != MAP_FAILED);
  for (size_t i = 0; i < bytes; i += 4096) pages[i] = 1;
  CHECK(getrusage(RUSAGE_SELF, &during) == 0 && during.ru_maxrss >= before.ru_maxrss
    && during.ru_maxrss >= (long)(bytes / 1024));
  CHECK(munmap((void *)pages, bytes) == 0);
  CHECK(getrusage(RUSAGE_SELF, &after) == 0 && after.ru_maxrss >= during.ru_maxrss);
  CHECK(getrusage(RUSAGE_CHILDREN, &children) == 0);
  long largest = children.ru_maxrss;
  for (int n = 1; n <= 2; ++n) {
    int sample[2]; CHECK(pipe(sample) == 0);
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
      close(sample[0]);
      size_t amount = n * bytes;
      volatile char *memory = mmap(NULL, amount, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (memory == MAP_FAILED) _exit(111);
      for (size_t i = 0; i < amount; i += 4096) memory[i] = 1;
      struct rusage own;
      if (getrusage(RUSAGE_SELF, &own) || munmap((void *)memory, amount)) _exit(112);
      if (write(sample[1], &own.ru_maxrss, sizeof(long)) != sizeof(long)) _exit(113);
      _exit(0);
    }
    CHECK(close(sample[1]) == 0);
    long measured; CHECK(read(sample[0], &measured, sizeof(measured)) == sizeof(measured));
    CHECK(close(sample[0]) == 0);
    struct rusage waited; int status;
    CHECK(wait4(child, &status, 0, &waited) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(waited.ru_maxrss >= measured && measured >= (long)(n * bytes / 1024));
    if (waited.ru_maxrss > largest) largest = waited.ru_maxrss;
    CHECK(getrusage(RUSAGE_CHILDREN, &children) == 0 && children.ru_maxrss == largest);
  }
  puts("rusage-memory: PASS native SELF peak retained, wait4 RSS, largest waited CHILDREN");
  return 0;
}

int mochi_wait_usage_probe(void) {
  CHECK(peak_usage() == 0);
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
