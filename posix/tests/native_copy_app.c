#define _GNU_SOURCE 1
#define _POSIX_THREADS 1
#define COPY_NATIVE 1
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "support/copy_root.c"

static __thread int cookie = 17;
static void check(int condition, const char *expression) {
  if (!condition) {
    fprintf(stderr, "copy-relocations: failed %s\n", expression);
    exit(1);
  }
}
#define CHECK(expression) check(!!(expression), #expression)
static void *thread_entry(void *unused) {
  (void)unused;
  CHECK(cookie == 17);
  cookie = 77;
  CHECK(check_copy() == 42);
  return (void *)(uintptr_t)1;
}
int main(int argc, char **argv) {
  const int after_exec = argc == 3 && strcmp(argv[1], "--after-exec") == 0;
  CHECK(argc == 2 || after_exec);
  const char *expected = argv[after_exec ? 2 : 1];
  CHECK(geteuid() == (strcmp(expected, "--expect-euid=501") == 0 ? 501 : 0));
  CHECK(cookie == 17 && check_copy() == 42);
  if (after_exec)
    return 42;
  CHECK(getenv("EXPECT_PARENT") && getppid() == atoi(getenv("EXPECT_PARENT")));
  cookie = 101;
  pthread_t thread;
  void *result = NULL;
  CHECK(pthread_create(&thread, NULL, thread_entry, NULL) == 0);
  CHECK(pthread_join(thread, &result) == 0 && result == (void *)(uintptr_t)1);
  CHECK(cookie == 101 && check_copy() == 42);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(cookie == 101 && check_copy() == 42);
    char *arguments[] = {argv[0], "--after-exec", (char *)expected, NULL};
    execv(argv[0], arguments);
    _exit(1);
  }
  int status = -1;
  CHECK(waitpid(child, &status, 0) == child && status == (42 << 8));
  CHECK(check_copy() == 42);
  puts("copy-relocations: native versioned data, relocated pointers, canonical addresses, BSS, pthread, fork/exec PASS");
  return 42;
}
