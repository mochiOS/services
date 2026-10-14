#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { printf("atfork: FAIL line=%d errno=%d\n", __LINE__, errno); return 1; } } while (0)
static char trace[32];
static unsigned position;
static atomic_int ready, stop;
static void note(char value) { if (position < sizeof(trace) - 1) trace[position++] = value; }
static void prepare_a(void) { note('a'); if (pthread_atfork(NULL, NULL, NULL)) note('!'); }
static void prepare_b(void) { note('b'); }
static void parent_a(void) { note('A'); errno = EIO; }
static void parent_b(void) { note('B'); }
static void child_a(void) { note('x'); if (pthread_atfork(NULL, NULL, NULL)) note('!'); }
static void child_b(void) { note('y'); }
static void *worker(void *unused) {
  (void)unused;
  atomic_store(&ready, 1);
  while (!atomic_load(&stop)) sched_yield();
  return NULL;
}
static int successful_fork(void) {
  memset(trace, 0, sizeof(trace)); position = 0;
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) _exit(strcmp(trace, "baxy") ? 1 : 0);
  CHECK(!strcmp(trace, "baAB"));
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  return 0;
}
int main(void) {
  CHECK(pthread_atfork(prepare_a, parent_a, child_a) == 0);
  CHECK(pthread_atfork(NULL, NULL, NULL) == 0);
  CHECK(pthread_atfork(prepare_b, parent_b, child_b) == 0);
  CHECK(successful_fork() == 0);
  pthread_t thread;
  CHECK(pthread_create(&thread, NULL, worker, NULL) == 0);
  while (!atomic_load(&ready)) sched_yield();
#ifdef __mochios__
  /* Multithread address-space cloning is still explicitly unsupported. */
  memset(trace, 0, sizeof(trace)); position = 0;
  CHECK(fork() == -1 && errno == EAGAIN);
  CHECK(!strcmp(trace, "baAB"));
  puts("atfork: PASS failed-fork parent cleanup and original errno");
#endif
  atomic_store(&stop, 1);
  CHECK(pthread_join(thread, NULL) == 0);
  CHECK(successful_fork() == 0);
  puts("atfork: PASS reverse preparation, ordered parent/child callbacks, reentrant registration and repeated forks");
  return 0;
}
