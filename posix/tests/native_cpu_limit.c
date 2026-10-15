#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "cpu-limit: FAIL line=%d errno=%d: %s\n", __LINE__,      \
              errno, #x);                                                      \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static volatile sig_atomic_t hits;
static volatile uint64_t work;
static atomic_int timed_out;
static pid_t watched;
static void caught(int signal) {
  if (signal == SIGXCPU)
    ++hits;
}
static uint64_t cpu_ns(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &value))
    _exit(41);
  return (uint64_t)value.tv_sec * UINT64_C(1000000000) +
         (uint64_t)value.tv_nsec;
}
static void burn(void) {
  for (unsigned index = 0; index < 100000; ++index)
    work = work * 6364136223846793005ULL + 1;
}
static void *watchdog(void *unused) {
  (void)unused;
  struct timespec remaining = {30, 0};
  while (nanosleep(&remaining, &remaining) && errno == EINTR) {
  }
  atomic_store(&timed_out, 1);
  kill(watched, SIGKILL);
  return NULL;
}
static void child(unsigned mode) {
  struct rlimit limit = {1, mode == 2 ? 5 : 2};
  if (mode == 1 || mode == 2) {
    struct sigaction action = {0};
    sigemptyset(&action.sa_mask);
    action.sa_handler = mode == 1 ? SIG_IGN : caught;
    if (sigaction(SIGXCPU, &action, NULL))
      _exit(42);
  }
  if (setrlimit(RLIMIT_CPU, &limit))
    _exit(44);
  if (mode == 3) {
    uint64_t before = cpu_ns();
    struct timespec remaining = {2, 200000000};
    while (nanosleep(&remaining, &remaining))
      if (errno != EINTR)
        _exit(45);
    if (cpu_ns() - before >= UINT64_C(1000000000))
      _exit(46);
    _exit(0);
  }
  if (mode == 4) {
    pid_t nested = fork();
    if (nested < 0)
      _exit(47);
    if (!nested)
      for (;;)
        burn();
    int status;
    if (waitpid(nested, &status, 0) != nested || !WIFSIGNALED(status) ||
        WTERMSIG(status) != SIGXCPU)
      _exit(48);
    _exit(0);
  }
  uint64_t first = 0;
  for (;;) {
    burn();
    if (mode == 2 && hits && !first)
      first = cpu_ns();
    if (mode == 2 && hits >= 2) {
      if (cpu_ns() - first < UINT64_C(950000000))
        _exit(49);
      _exit(0);
    }
  }
}
int main(void) {
  fprintf(
      stderr,
      "cpu-limit: start native CPU accounting and asynchronous enforcement\n");
  struct rlimit before, after;
  CHECK(getrlimit(RLIMIT_CPU, &before) == 0);
  for (unsigned mode = 0; mode < 5; ++mode) {
    atomic_store(&timed_out, 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (!pid)
      child(mode);
    watched = pid;
    pthread_t timer;
    CHECK(pthread_create(&timer, NULL, watchdog, NULL) == 0);
    int status;
    pid_t waited;
    do {
      waited = waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);
    CHECK(waited == pid && !atomic_load(&timed_out));
    CHECK(pthread_cancel(timer) == 0);
    void *result;
    CHECK(pthread_join(timer, &result) == 0 && result == PTHREAD_CANCELED);
    CHECK(mode >= 2 ? WIFEXITED(status) && WEXITSTATUS(status) == 0
                    : WIFSIGNALED(status) &&
                          WTERMSIG(status) == (mode == 0 ? SIGXCPU : SIGKILL));
    CHECK(getrlimit(RLIMIT_CPU, &after) == 0 &&
          before.rlim_cur == after.rlim_cur &&
          before.rlim_max == after.rlim_max);
    fprintf(stderr, "cpu-limit: mode=%u PASS\n", mode);
  }
  puts("cpu-limit: PASS default soft signal, ignored soft/hard kill, repeated "
       "caught signal, sleeping time and fork inheritance");
  return 0;
}
