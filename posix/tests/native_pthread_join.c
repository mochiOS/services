#define _GNU_SOURCE 1
#define _POSIX_THREADS 1
#define _POSIX_TIMERS 1
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static pthread_t target, main_thread;
static _Atomic unsigned gate, ready, cleanup_started, cleanup_ok, returned, mode;
static _Atomic int fork_pid, fork_ok;
static volatile sig_atomic_t fork_child;
static sigjmp_buf escape;
static __thread unsigned cookie = 17;
static void check(int condition, unsigned line) {
  if (!condition) {
    fprintf(stderr, "pthread-join: FAIL line=%u errno=%d\n", line, errno);
    exit(1);
  }
}
#define CHECK(expression) check(!!(expression), __LINE__)
static void delay(void) {
  struct timespec time = {0, 10000000};
  CHECK(nanosleep(&time, NULL) == 0);
}
static void await(_Atomic unsigned *flag) {
  while (!atomic_load(flag))
    sched_yield();
}
static void *quick(void *unused) {
  (void)unused;
  CHECK(cookie == 17);
  cookie = 42;
  return (void *)(uintptr_t)55;
}
static void *gated(void *unused) {
  (void)unused;
  await(&gate);
  return quick(NULL);
}
static void cleanup_join(void *unused) {
  (void)unused;
  atomic_store(&cleanup_started, 1);
  void *result = NULL;
  CHECK(pthread_join(target, &result) == 0 && result == (void *)(uintptr_t)55);
  atomic_store(&cleanup_ok, 1);
}
static void *cancel_join(void *asynchronous) {
  void *result = (void *)(uintptr_t)99;
  pthread_cleanup_push(cleanup_join, NULL);
  if (asynchronous)
    CHECK(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL) == 0);
  atomic_store(&ready, 1);
  CHECK(pthread_join(target, &result) == 0);
  atomic_store(&returned, 1);
  pthread_cleanup_pop(0);
  return result;
}
static void handler(int signal) {
  (void)signal;
  if (atomic_load(&mode) == 1)
    siglongjmp(escape, 1);
  pid_t child = fork();
  if (child < 0)
    _exit(91);
  if (child == 0) {
    fork_child = 1;
    alarm(10);
  } else {
    atomic_store(&fork_pid, child);
  }
}
static void *signaler(void *forking) {
  delay();
  CHECK(pthread_kill(main_thread, SIGUSR1) == 0);
  if (forking) {
    int child;
    while (!(child = atomic_load(&fork_pid)))
      sched_yield();
    int status = -1;
    CHECK(waitpid(child, &status, 0) == child && status == 0);
    atomic_store(&fork_ok, 1);
    atomic_store(&gate, 1);
  }
  return NULL;
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  CHECK(geteuid() == (strcmp(argv[1], "--expect-euid=501") == 0 ? 501 : 0));
  alarm(60);
  main_thread = pthread_self();
  const size_t page = (size_t)sysconf(_SC_PAGESIZE);
  unsigned char *memory = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(memory != MAP_FAILED);
  CHECK(mprotect(memory + page, page, PROT_NONE) == 0);
  for (unsigned n = 0; n != 32; ++n) {
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, quick, NULL) == 0);
    CHECK(pthread_join(thread, (void **)1) == EFAULT);
    CHECK(pthread_join(thread, (void **)(memory + page)) == EFAULT);
    CHECK(pthread_join(thread, (void **)(memory + page - 1)) == EFAULT);
    CHECK(mprotect(memory, page, PROT_READ) == 0);
    CHECK(pthread_join(thread, (void **)memory) == EFAULT);
    CHECK(mprotect(memory, page, PROT_READ | PROT_WRITE) == 0);
    CHECK(pthread_join(thread, (void **)(memory + 1)) == 0);
    void *result = NULL;
    memcpy(&result, memory + 1, sizeof(result));
    CHECK(result == (void *)(uintptr_t)55);
  }
  CHECK(munmap(memory, page * 2) == 0);
  for (unsigned n = 0; n != 8; ++n) {
    atomic_store(&gate, 0);
    atomic_store(&ready, 0);
    atomic_store(&cleanup_started, 0);
    atomic_store(&cleanup_ok, 0);
    atomic_store(&returned, 0);
    pthread_t waiter;
    CHECK(pthread_create(&target, NULL, gated, NULL) == 0);
    CHECK(pthread_create(&waiter, NULL, cancel_join, (void *)(uintptr_t)(n % 2)) == 0);
    await(&ready);
    delay();
    CHECK(pthread_cancel(waiter) == 0);
    await(&cleanup_started);
    CHECK(atomic_load(&returned) == 0);
    atomic_store(&gate, 1);
    void *result = NULL;
    CHECK(pthread_join(waiter, &result) == 0 && result == PTHREAD_CANCELED);
    CHECK(atomic_load(&cleanup_ok) == 1);
  }
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = handler;
  CHECK(sigemptyset(&action.sa_mask) == 0);
  CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
  atomic_store(&mode, 1);
  atomic_store(&gate, 0);
  pthread_t sender;
  CHECK(pthread_create(&target, NULL, gated, NULL) == 0);
  CHECK(pthread_create(&sender, NULL, signaler, NULL) == 0);
  if (sigsetjmp(escape, 1) == 0) {
    CHECK(pthread_join(target, NULL) == 0);
    CHECK(0);
  }
  atomic_store(&gate, 1);
  void *result = NULL;
  CHECK(pthread_join(target, &result) == 0 && result == (void *)(uintptr_t)55);
  CHECK(pthread_join(sender, NULL) == 0);

  atomic_store(&mode, 2);
  atomic_store(&gate, 0);
  CHECK(pthread_create(&target, NULL, gated, NULL) == 0);
  CHECK(pthread_create(&sender, NULL, signaler, (void *)1) == 0);
  result = (void *)(uintptr_t)99;
  int status = pthread_join(target, &result);
  if (fork_child) {
    CHECK(status == ESRCH && result == (void *)(uintptr_t)99);
    pthread_t fresh;
    CHECK(pthread_create(&fresh, NULL, quick, NULL) == 0);
    CHECK(pthread_join(fresh, &result) == 0 && result == (void *)(uintptr_t)55);
    _exit(0);
  }
  CHECK(status == 0 && result == (void *)(uintptr_t)55);
  CHECK(pthread_join(sender, NULL) == 0 && atomic_load(&fork_ok) == 1);
  alarm(0);
  puts("pthread-join: PASS output faults/retry, unaligned output, deferred/async "
       "cancellation cleanup, siglongjmp, handler fork and child slot reuse");
  return 0;
}
