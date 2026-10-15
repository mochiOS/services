/* No test hook in libc: escape only after observing a new owned Handle while
 * the expected FD is still absent. This identifies the real pre-publication
 * open boundary, rather than counting an unrelated signal as coverage. */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "open-signal-escape: FAIL line=%u errno=%d: %s\n",       \
              __LINE__, errno, #x);                                             \
      return 1;                                                                \
    }                                                                          \
  } while (0)

_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal-safe handshake");
_Static_assert(sizeof(sigjmp_buf) == 120, "native signal jump ABI");
struct handle_info {
  uint32_t handle, reserved;
  uint64_t rights;
};
static struct handle_info records[4096];
static sigjmp_buf escape;
static atomic_int armed, stopping, ready, busy, sender_error;
static atomic_uint deliveries;
static volatile sig_atomic_t handler_error, escapes;
static pthread_t target;
static int expected_fd;
static long baseline;
static unsigned baseline_waits;

/* Generic metadata for this process's own Handles. It acquires no references
 * and cannot name another process, service, pathname or POSIX descriptor. */
static long snapshot(unsigned *waits) {
  uint64_t result = 680; /* HandleTableRead */
  __asm__ volatile("syscall"
                   : "+a"(result)
                   : "D"((uintptr_t)records), "S"((uint64_t)4096)
                   : "rcx", "r11", "memory");
  if ((int64_t)result < 0 || result > 4096)
    return -1;
  *waits = 0;
  for (unsigned i = 0; i < result; ++i) {
    if (records[i].reserved || !records[i].handle)
      return -1;
    if (records[i].rights == ((UINT64_C(1) << 63) | 16))
      ++*waits;
  }
  return (long)result;
}

static void handler(int signal) {
  int previous_errno = errno;
  atomic_fetch_add_explicit(&deliveries, 1, memory_order_release);
  if (signal != SIGUSR1)
    handler_error = 1;
  if (atomic_load_explicit(&armed, memory_order_acquire)) {
    unsigned waits;
    long count = snapshot(&waits);
    if (count < 0 || waits != baseline_waits) {
      /* In particular, libc must close its wait ticket BEFORE dispatching C. */
      handler_error = 2;
      atomic_store_explicit(&armed, 0, memory_order_release);
      siglongjmp(escape, 37);
    }
    if (count == baseline + 1 && fcntl(expected_fd, F_GETFD) == -1 &&
        errno == EBADF) {
      ++escapes;
      atomic_store_explicit(&armed, 0, memory_order_release);
      siglongjmp(escape, 37);
    }
  }
  errno = previous_errno;
}

static void *send_signals(void *unused) {
  (void)unused;
  int error = pthread_kill(target, 0); /* Finish thread registration first. */
  if (error)
    atomic_store(&sender_error, error);
  atomic_store_explicit(&ready, 1, memory_order_release);
  while (!atomic_load_explicit(&stopping, memory_order_acquire)) {
    if (!atomic_load_explicit(&armed, memory_order_acquire)) {
      sched_yield();
      continue;
    }
    atomic_store_explicit(&busy, 1, memory_order_release);
    unsigned before = atomic_load_explicit(&deliveries, memory_order_acquire);
    error = pthread_kill(target, SIGUSR1);
    if (error) {
      atomic_store(&sender_error, error);
      break;
    }
    while (atomic_load_explicit(&armed, memory_order_acquire) &&
           !atomic_load_explicit(&stopping, memory_order_acquire) &&
           atomic_load_explicit(&deliveries, memory_order_acquire) == before)
      sched_yield();
    atomic_store_explicit(&busy, 0, memory_order_release);
  }
  atomic_store_explicit(&busy, 0, memory_order_release);
  return NULL;
}

int main(void) {
  fprintf(stderr, "open-signal-escape: starting tracked open escapes\n");
  char path[] = "/tmp/open-signal-escape-XXXXXX";
  int source = mkstemp(path);
  CHECK(source >= 0);
  int probe = open(path, O_RDONLY);
  CHECK(probe >= 0);
  expected_fd = probe;
  CHECK(close(probe) == 0);
  target = pthread_self();
  struct sigaction action = {0};
  sigemptyset(&action.sa_mask);
  action.sa_handler = handler;
  action.sa_flags = SA_RESTART;
  CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
  sigset_t empty;
  sigemptyset(&empty);
  CHECK(pthread_sigmask(SIG_SETMASK, &empty, NULL) == 0);
  pthread_t sender;
  CHECK(pthread_create(&sender, NULL, send_signals, NULL) == 0);
  while (!atomic_load_explicit(&ready, memory_order_acquire))
    CHECK(sched_yield() == 0);
  CHECK(atomic_load(&sender_error) == 0);
  CHECK(raise(SIGUSR1) == 0); /* Warm the signal path before counting Handles. */
  baseline = snapshot(&baseline_waits);
  CHECK(baseline > 0);
  for (volatile unsigned round = 0; round < 16; ++round) {
    int result = sigsetjmp(escape, 1);
    if (!result) {
      atomic_store_explicit(&armed, 1, memory_order_release);
      for (unsigned attempt = 0; attempt < 256; ++attempt) {
        int opened = open(path, O_RDWR | O_TRUNC);
        CHECK(opened == expected_fd);
        CHECK(close(opened) == 0);
      }
      atomic_store_explicit(&armed, 0, memory_order_release);
      CHECK(0); /* No qualifying ownership boundary was observed. */
    }
    CHECK(result == 37 && !handler_error);
    while (atomic_load_explicit(&busy, memory_order_acquire))
      CHECK(sched_yield() == 0);
    CHECK(atomic_load(&sender_error) == 0);
    unsigned waits;
    CHECK(snapshot(&waits) == baseline && waits == baseline_waits);
    CHECK(fcntl(expected_fd, F_GETFD) == -1 && errno == EBADF);
    probe = open(path, O_RDONLY);
    CHECK(probe == expected_fd && close(probe) == 0);
  }
  atomic_store_explicit(&stopping, 1, memory_order_release);
  CHECK(pthread_join(sender, NULL) == 0);
  CHECK(escapes == 16 && !handler_error && !atomic_load(&sender_error));
  CHECK(close(source) == 0 && unlink(path) == 0);
  printf("open-signal-escape: PASS %d observed owned-reply escapes; Handles and "
         "FD reservations reclaimed\n", (int)escapes);
  return 0;
}
