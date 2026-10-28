#define _GNU_SOURCE 1
#define _POSIX_THREADS 1
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "dso-tls: FAIL line=%d errno=%d: %s\n", __LINE__, errno, \
              #x);                                                             \
      return 1;                                                                \
    }                                                                          \
  } while (0)
__thread int tls_root = 11;
__thread int tls_interpose = 17;
static __thread char root_zero[73] __attribute__((aligned(64)));
extern int *tls_general_address(void);
extern int *tls_interpose_address(void);
extern int *tls_local_address(void);
extern int *tls_initial_address(void);
extern int *tls_root_address(void);
extern char *tls_zero_address(void);
#ifdef TLS_DESCRIPTOR
extern int *tls_missing_address(void);
#endif
static int constructor_ok;
static atomic_int ready;
static int fresh(void) {
#ifdef TLS_DESCRIPTOR
  CHECK(tls_missing_address() == NULL);
#endif
  CHECK(tls_root == 11 && tls_interpose == 17);
  CHECK(*tls_general_address() == 23 && *tls_local_address() == 41);
  CHECK(tls_interpose_address() == &tls_interpose);
  CHECK(tls_initial_address() == tls_general_address());
  CHECK(tls_root_address() == &tls_root);
  CHECK((uintptr_t)tls_zero_address() % 8192 == 0);
  for (unsigned i = 0; i < sizeof(root_zero); ++i)
    CHECK(root_zero[i] == 0);
  for (unsigned i = 0; i < 8195; ++i)
    CHECK(tls_zero_address()[i] == 0);
  return 0;
}
__attribute__((constructor)) static void initialize(void) {
  constructor_ok = fresh() == 0;
}
static void *worker(void *argument) {
  intptr_t tag = (intptr_t)argument;
  if (fresh())
    return (void *)1;
  if (tag == 0)
    return NULL;
  tls_root = 100 + tag;
  *tls_general_address() = 200 + tag;
  *tls_local_address() = 300 + tag;
  tls_zero_address()[42] = tag;
  root_zero[3] = tag;
  atomic_fetch_add_explicit(&ready, 1, memory_order_release);
  while (atomic_load_explicit(&ready, memory_order_acquire) != 2)
    usleep(1000);
  return (void *)(uintptr_t) !(
      tls_root == 100 + tag && *tls_general_address() == 200 + tag &&
      *tls_local_address() == 300 + tag && tls_zero_address()[42] == tag &&
      root_zero[3] == tag);
}
int main(int argc, char **arguments) {
  CHECK(argc == 2);
  CHECK(geteuid() == (strcmp(arguments[1], "--expect-euid=0") == 0 ? 0 : 501));
  CHECK(constructor_ok && fresh() == 0);
  CHECK(getauxval(0x6d000006) != 0);
  alarm(120);
  tls_root = 31;
  *tls_general_address() = 51;
  *tls_local_address() = 61;
  tls_zero_address()[42] = 17;
  root_zero[3] = 19;
  pthread_t threads[2];
  CHECK(pthread_create(&threads[0], NULL, worker, (void *)1) == 0);
  CHECK(pthread_create(&threads[1], NULL, worker, (void *)2) == 0);
  for (unsigned i = 0; i < 2; ++i) {
    void *result = (void *)1;
    CHECK(pthread_join(threads[i], &result) == 0 && result == NULL);
  }
  CHECK(tls_root == 31 && *tls_general_address() == 51 &&
        *tls_local_address() == 61);
  CHECK(tls_zero_address()[42] == 17 && root_zero[3] == 19);
  puts("dso-tls: PASS GD/LD/IE, preemption, constructors and per-thread "
       "isolation");
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    if (tls_root != 31 || *tls_general_address() != 51 ||
        *tls_local_address() != 61)
      _exit(81);
    *tls_general_address() = 99;
    tls_root = 98;
    pthread_t thread;
    void *result = (void *)1;
    if (pthread_create(&thread, NULL, worker, NULL) ||
        pthread_join(thread, &result) || result)
      _exit(82);
    _exit(0);
  }
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  CHECK(tls_root == 31 && *tls_general_address() == 51 &&
        *tls_local_address() == 61);
  puts("dso-tls: PASS fork COW and fresh TLS in a post-fork pthread");
  return 42;
}
