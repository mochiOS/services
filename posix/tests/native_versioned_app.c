#define _GNU_SOURCE 1
#define _POSIX_THREADS 1
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define _start versioned_entry
#include "support/versioned_root.c"
#undef _start

static void check(int condition, const char *expression) {
  if (!condition) {
    fprintf(stderr, "symbol-versions: failed %s\n", expression);
    exit(1);
  }
}
#define CHECK(expression) check(!!(expression), #expression)

static void *thread_entry(void *unused) {
  (void)unused;
#ifdef VERSIONED_TLS
  CHECK(read_tls() == 50);
  legacy_tls = 21;
  current_tls = 43;
  CHECK(read_tls() == 64);
#endif
  return (void *)(uintptr_t)1;
}

int main(int argc, char **argv) {
  const int after_exec = argc == 3 && strcmp(argv[1], "--after-exec") == 0;
  CHECK(argc == 2 || after_exec);
  const char *expected = argv[after_exec ? 2 : 1];
  CHECK(geteuid() == (strcmp(expected, "--expect-euid=501") == 0 ? 501 : 0));
#ifdef UNVERSIONED_REFERENCE
  CHECK(versioned_entry() == 15);
#elif defined(ROOT_PREEMPTION)
  CHECK(versioned_entry() == 1201);
#else
  CHECK(versioned_entry() == 75);
#endif
#ifdef VERSIONED_TLS
  CHECK(read_tls() == 50);
#endif
  if (after_exec)
    return 42;
  CHECK(getenv("EXPECT_PARENT") && getppid() == atoi(getenv("EXPECT_PARENT")));
  pthread_t thread;
  void *result = NULL;
  CHECK(pthread_create(&thread, NULL, thread_entry, NULL) == 0);
  CHECK(pthread_join(thread, &result) == 0 && result == (void *)(uintptr_t)1);
#ifdef VERSIONED_TLS
  CHECK(read_tls() == 50);
#endif
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
#ifdef VERSIONED_TLS
    CHECK(read_tls() == 50);
#endif
    char *arguments[] = {argv[0], "--after-exec", (char *)expected, NULL};
    execv(argv[0], arguments);
    _exit(1);
  }
  int status = -1;
  CHECK(waitpid(child, &status, 0) == child && status == (42 << 8));
  puts("symbol-versions: native old/new code/data, TLS, pthread, fork/exec PASS");
  return 42;
}
