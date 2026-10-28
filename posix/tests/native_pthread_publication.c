#define _GNU_SOURCE 1
#define _POSIX_THREADS 1
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(sizeof(pthread_attr_t) == 40, "opaque attributes ABI");
static _Atomic unsigned callbacks;
static __thread unsigned cookie = 17;
static void check(int condition, unsigned line) {
  if (!condition) {
    fprintf(stderr, "pthread-publication: FAIL line=%u errno=%d\n", line, errno);
    exit(1);
  }
}
#define CHECK(expression) check(!!(expression), __LINE__)
static void *count(void *detach_self) {
  CHECK(cookie == 17);
  cookie = 42;
  if (detach_self)
    CHECK(pthread_detach(pthread_self()) == 0);
  atomic_fetch_add(&callbacks, 1);
  return (void *)(uintptr_t)42;
}
static void create(pthread_t *thread, const pthread_attr_t *attributes,
                   void *argument) {
  for (unsigned attempt = 0; attempt != 10000; ++attempt) {
    int status = pthread_create(thread, attributes, count, argument);
    if (status == EAGAIN) {
      sched_yield();
      continue;
    }
    CHECK(status == 0);
    return;
  }
  CHECK(0);
}
static void *creator(void *unused) {
  (void)unused;
  pthread_attr_t attr;
  CHECK(pthread_attr_init(&attr) == 0);
  CHECK(pthread_attr_setstacksize(&attr, 64 * 1024) == 0);
  CHECK(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) == 0);
  for (unsigned n = 0; n != 40; ++n) {
    pthread_t child;
    // Include children detaching themselves before the creator returns.
    create(&child, n % 2 ? NULL : &attr, (void *)(uintptr_t)(n % 2));
  }
  CHECK(pthread_attr_destroy(&attr) == 0);
  return NULL;
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  CHECK(geteuid() == (strcmp(argv[1], "--expect-euid=501") == 0 ? 501 : 0));
  alarm(60);
  const size_t page = (size_t)sysconf(_SC_PAGESIZE);
  unsigned char *memory = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(memory != MAP_FAILED);
  CHECK(mprotect(memory + page, page, PROT_NONE) == 0);
  pthread_attr_t attr;
  CHECK(pthread_attr_init(&attr) == 0);
  CHECK(pthread_attr_setstacksize(&attr, 64 * 1024) == 0);
  pthread_t thread;
  for (unsigned n = 0; n != 80; ++n) {
    CHECK(pthread_create((pthread_t *)1, &attr, count, NULL) == EFAULT);
    CHECK(pthread_create((pthread_t *)(memory + page), &attr, count, NULL) == EFAULT);
    CHECK(pthread_create((pthread_t *)(memory + page - 1), &attr, count, NULL) == EFAULT);
    CHECK(pthread_create(&thread, (pthread_attr_t *)(memory + page), count, NULL) == EFAULT);
  }
  CHECK(atomic_load(&callbacks) == 0);
  CHECK(mprotect(memory, page, PROT_READ) == 0);
  CHECK(pthread_create((pthread_t *)memory, &attr, count, NULL) == EFAULT);
  CHECK(atomic_load(&callbacks) == 0);
  CHECK(mprotect(memory, page, PROT_READ | PROT_WRITE) == 0);
  create((pthread_t *)(memory + 1), &attr, NULL);
  memcpy(&thread, memory + 1, sizeof(thread));
  void *result = NULL;
  CHECK(pthread_join(thread, &result) == 0 && result == (void *)(uintptr_t)42);
  CHECK(atomic_load(&callbacks) == 1);
  CHECK(pthread_attr_destroy(&attr) == 0);

  pthread_t workers[4];
  for (unsigned n = 0; n != 4; ++n)
    CHECK(pthread_create(&workers[n], NULL, creator, NULL) == 0);
  for (unsigned n = 0; n != 4; ++n) {
    result = (void *)1;
    CHECK(pthread_join(workers[n], &result) == 0 && result == NULL);
  }
  while (atomic_load(&callbacks) != 161)
    sched_yield();
  // Continued creation forces retirement/reuse of the bounded TCB table.
  for (unsigned n = 0; n != 100; ++n) {
    create(&thread, NULL, NULL);
    CHECK(pthread_join(thread, &result) == 0 && result == (void *)(uintptr_t)42);
  }
  CHECK(atomic_load(&callbacks) == 261);
  CHECK(cookie == 17);
  pid_t child = fork();
  CHECK(child >= 0);
  if (!child) {
    create(&thread, NULL, NULL);
    CHECK(pthread_join(thread, &result) == 0 && result == (void *)(uintptr_t)42);
    _exit(0);
  }
  int status = -1;
  CHECK(waitpid(child, &status, 0) == child && status == 0);
  CHECK(munmap(memory, page * 2) == 0);
  alarm(0);
  puts("pthread-publication: PASS failed output without child, attribute faults, "
       "unaligned output, detached/self-detached creation, concurrent reuse, TLS and fork");
  return 0;
}
