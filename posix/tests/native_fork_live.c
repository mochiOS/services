/* Real mochiOS integration. Link with the fresh runtime, then run on mochiOS;
 * host execution cannot validate native COW, Handle inheritance or exec. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <pthread.h>
#include <reent.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "fork-live: FAIL line=%d errno=%d\n", __LINE__, errno);  \
      return 1;                                                                \
    }                                                                          \
  } while (0)
extern char **environ;
static atomic_int ready, stop, cleaned, tls_cleaned, worker_error;
static pthread_key_t key;
static struct _reent *foreign_reent;
static void cleanup(struct _reent *unused) {
  (void)unused;
  atomic_fetch_add(&cleaned, 1);
}
static void tls_cleanup(void *value) {
  if (value != (void *)(uintptr_t)17)
    atomic_store(&worker_error, 1);
  atomic_fetch_add(&tls_cleaned, 1);
}
static void *worker(void *unused) {
  (void)unused;
  struct _reent *reent = __getreent();
  if (_REENT_CVTBUF(reent) || pthread_setspecific(key, (void *)(uintptr_t)17)) {
    atomic_store(&worker_error, 1);
    atomic_store_explicit(&ready, 1, memory_order_release);
    return NULL;
  }
  // Deliberately model an interrupted cache update. Neither fork-child
  // cleanup nor a TLS destructor may try to follow this private pointer.
  _REENT_CVTBUF(reent) = (char *)(uintptr_t)1;
  _REENT_CLEANUP(reent) = cleanup;
  foreign_reent = reent;
  atomic_store_explicit(&ready, 1, memory_order_release);
  while (!atomic_load_explicit(&stop, memory_order_acquire))
    sched_yield();
  _REENT_CVTBUF(reent) = NULL; // parent exit/join may now reclaim normally
  return NULL;
}
int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--fork-child") == 0)
    return 0;
  CHECK(argc >= 1 && argv[0] && *argv[0]);
  CHECK(pthread_key_create(&key, tls_cleanup) == 0);
  pthread_t thread;
  CHECK(pthread_create(&thread, NULL, worker, NULL) == 0);
  while (!atomic_load_explicit(&ready, memory_order_acquire))
    sched_yield();
  CHECK(!atomic_load(&worker_error) && foreign_reent);
  for (unsigned round = 0; round < 3; ++round) {
    int channel[2];
    CHECK(pipe(channel) == 0);
    pid_t child = -1;
    for (unsigned attempt = 0; attempt < 100; ++attempt) {
      child = fork();
      if (child >= 0 || errno != EAGAIN)
        break;
      sched_yield();
    }
    CHECK(child >= 0);
    if (child == 0) {
      // No allocation, stdio, foreign TLS destruction or cache walk
      // occurs between the multithreaded fork and execve.
      if (atomic_load(&cleaned) || atomic_load(&tls_cleaned))
        _exit(51);
      if (_REENT_CVTBUF(foreign_reent) != (char *)(uintptr_t)1)
        _exit(52);
      char marker = 'C';
      if (close(channel[0]) || write(channel[1], &marker, 1) != 1 ||
          close(channel[1]))
        _exit(53);
      char *arguments[] = {argv[0], "--fork-child", NULL};
      execve(argv[0], arguments, environ);
      _exit(54);
    }
    CHECK(close(channel[1]) == 0);
    char marker = 0;
    CHECK(read(channel[0], &marker, 1) == 1 && marker == 'C');
    CHECK(close(channel[0]) == 0);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status));
    if (WEXITSTATUS(status))
      fprintf(stderr, "fork-live: child status=%d\n", WEXITSTATUS(status));
    CHECK(WEXITSTATUS(status) == 0);
    CHECK(!atomic_load(&cleaned) && !atomic_load(&tls_cleaned));
  }
  atomic_store_explicit(&stop, 1, memory_order_release);
  CHECK(pthread_join(thread, NULL) == 0);
  CHECK(!atomic_load(&worker_error));
  CHECK(atomic_load(&cleaned) == 1 && atomic_load(&tls_cleaned) == 1);
  CHECK(pthread_key_delete(key) == 0);
  puts("fork-live: PASS live sibling, opaque caches, parent-only destructors, "
       "inherited pipe and child exec");
  return 0;
}
