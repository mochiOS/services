/* Exit only after observing an unpublished file reply. Application cleanup
 * then verifies that runtime ownership was released BEFORE it was called. */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr,                                                          \
              "open-thread-exit: FAIL line=%u errno=%d fault=%d: %s\n",        \
              __LINE__, errno, atomic_load(&fault), #x);                       \
      return 1;                                                                \
    }                                                                          \
  } while (0)
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal-safe handshake");
struct handle_info {
  uint32_t handle, reserved;
  uint64_t rights;
};
static struct handle_info records[128];
static uint32_t baseline_handles[128];
static const char *filename;
static int expected_fd;
static long baseline;
static unsigned baseline_waits;
static unsigned mode;
static _Atomic(pthread_t) target;
static atomic_uint active, go, deliveries, abandoned, escapes, cleanups,
    returned;
static atomic_int fault, stopping, sender_ready, sender_busy, worker_ready;

static long snapshot(unsigned *waits) {
  uint64_t number = 680; /* HandleTableRead: this process's own metadata. */
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"((uintptr_t)records), "S"((uint64_t)128)
                   : "rcx", "r11", "memory");
  if ((int64_t)number < 0 || number > 128)
    return -1;
  *waits = 0;
  for (unsigned i = 0; i < number; ++i) {
    if (!records[i].handle || records[i].reserved)
      return -1;
    if (records[i].rights == ((UINT64_C(1) << 63) | 16))
      ++*waits;
  }
  return (long)number;
}

static int was_present(uint32_t handle) {
  for (long i = 0; i < baseline; ++i)
    if (baseline_handles[i] == handle)
      return 1;
  return 0;
}

static void cleanup(void *unused) {
  (void)unused;
  unsigned waits;
  long count = snapshot(&waits);
  uint32_t retired = atomic_load(&abandoned);
  if ((mode != 3 && !retired) || count != baseline || waits != baseline_waits) {
    atomic_store(&fault, 4);
    return;
  }
  for (long i = 0; i < count; ++i) {
    if ((retired && records[i].handle == retired) ||
        !was_present(records[i].handle)) {
      atomic_store(&fault, 5);
      return;
    }
  }
  if (fcntl(expected_fd, F_GETFD) != -1 || errno != EBADF) {
    atomic_store(&fault, 6);
    return;
  }
  // Reenter libc from application cleanup after the interrupted scope retired.
  int fd = open(filename, O_RDONLY);
  if (fd != expected_fd || close(fd)) {
    atomic_store(&fault, 7);
    return;
  }
  atomic_fetch_add(&cleanups, 1);
}

static void handler(int signal) {
  int previous = errno;
  atomic_fetch_add_explicit(&deliveries, 1, memory_order_release);
  if (signal != SIGUSR1)
    atomic_store(&fault, 1);
  if (atomic_load_explicit(&active, memory_order_acquire)) {
    unsigned waits;
    long count = snapshot(&waits);
    if (count < 0 || waits != baseline_waits)
      atomic_store(&fault, 2);
    if (count == baseline + 1 && fcntl(expected_fd, F_GETFD) == -1 &&
        errno == EBADF) {
      uint32_t file = 0;
      for (long i = 0; i < count; ++i) {
        if (!was_present(records[i].handle)) {
          if (file || (records[i].rights & 131) != 131) {
            file = 0;
            break;
          }
          file = records[i].handle; // READ | WRITE | SEEK, not a wait object.
        }
      }
      if (file) {
        atomic_store(&abandoned, file);
        atomic_store_explicit(&active, 0, memory_order_release);
        atomic_fetch_add(&escapes, 1);
        if (mode == 0)
          pthread_exit((void *)0x55);
        if (pthread_cancel(pthread_self()))
          atomic_store(&fault, 10);
      }
    }
  }
  errno = previous;
}

static void *worker(void *argument) {
  unsigned epoch = (unsigned)(uintptr_t)argument;
  sigset_t signal;
  sigemptyset(&signal);
  sigaddset(&signal, SIGUSR1);
  int fd = open(filename, O_RDONLY);
  if (fd != expected_fd || close(fd) ||
      pthread_sigmask(SIG_UNBLOCK, &signal, NULL) || raise(SIGUSR1)) {
    atomic_store(&fault, 3);
    return (void *)1;
  }
  if (mode == 2 && pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL)) {
    atomic_store(&fault, 11);
    return (void *)1;
  }
  pthread_cleanup_push(cleanup, NULL);
  atomic_store_explicit(&worker_ready, 1, memory_order_release);
  while (atomic_load_explicit(&go, memory_order_acquire) != epoch)
    sched_yield();
  if (mode == 3) {
    if (pthread_cancel(pthread_self()))
      atomic_store(&fault, 12);
  } else
    atomic_store_explicit(&active, epoch, memory_order_release);
  for (unsigned attempt = 0; attempt < 256; ++attempt) {
    fd = open(filename, O_RDWR | O_TRUNC);
    if (mode == 3 || atomic_load(&abandoned))
      atomic_store(&returned, 1);
    if (fd != expected_fd || close(fd)) {
      atomic_store(&fault, 8);
      break;
    }
    if (mode == 2 && atomic_load(&abandoned)) {
      if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL))
        atomic_store(&fault, 13);
      pthread_testcancel();
      break;
    }
  }
  atomic_store_explicit(&active, 0, memory_order_release);
  pthread_cleanup_pop(0);
  return (void *)2; // No observed ownership boundary: never count as coverage.
}

static void *sender(void *unused) {
  (void)unused;
  if (pthread_kill(pthread_self(), 0))
    atomic_store(&fault, 9);
  atomic_store_explicit(&sender_ready, 1, memory_order_release);
  while (!atomic_load_explicit(&stopping, memory_order_acquire)) {
    unsigned epoch = atomic_load_explicit(&active, memory_order_acquire);
    if (!epoch) {
      sched_yield();
      continue;
    }
    atomic_store_explicit(&sender_busy, 1, memory_order_release);
    unsigned before = atomic_load_explicit(&deliveries, memory_order_acquire);
    if (atomic_load_explicit(&active, memory_order_acquire) == epoch) {
      int error = pthread_kill(
          atomic_load_explicit(&target, memory_order_acquire), SIGUSR1);
      // An extra notification may race the observed target's normal exit.
      if (error && atomic_load_explicit(&active, memory_order_acquire) == epoch)
        atomic_store(&fault, error);
    }
    while (atomic_load_explicit(&active, memory_order_acquire) == epoch &&
           !atomic_load_explicit(&stopping, memory_order_acquire) &&
           atomic_load_explicit(&deliveries, memory_order_acquire) == before)
      sched_yield();
    atomic_store_explicit(&sender_busy, 0, memory_order_release);
  }
  return NULL;
}

int main(void) {
  fprintf(stderr, "open-thread-exit: starting observed reply abandonment\n");
  char path[] = "/tmp/open-thread-exit-XXXXXX";
  int source = mkstemp(path);
  CHECK(source >= 0);
  filename = path;
  int probe = open(path, O_RDONLY);
  CHECK(probe >= 0 && close(probe) == 0);
  expected_fd = probe;
  struct sigaction action = {0};
  sigemptyset(&action.sa_mask);
  action.sa_handler = handler;
  action.sa_flags = SA_RESTART;
  CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
  sigset_t blocked;
  sigemptyset(&blocked);
  sigaddset(&blocked, SIGUSR1);
  CHECK(pthread_sigmask(SIG_BLOCK, &blocked, NULL) == 0);
  pthread_t notifier;
  CHECK(pthread_create(&notifier, NULL, sender, NULL) == 0);
  while (!atomic_load_explicit(&sender_ready, memory_order_acquire))
    CHECK(!atomic_load(&fault) && sched_yield() == 0);
  unsigned iteration = 0, expected_escapes = 0;
  for (mode = 0; mode < 4; ++mode) {
    for (unsigned cycle = 0; cycle < (mode < 2 ? 16u : 4u); ++cycle) {
      CHECK(ftruncate(source, 8192) == 0);
      atomic_store(&worker_ready, 0);
      atomic_store(&abandoned, 0);
      atomic_store(&returned, 0);
      pthread_t thread;
      CHECK(pthread_create(&thread, NULL, worker,
                           (void *)(uintptr_t)(iteration + 1)) == 0);
      while (!atomic_load_explicit(&worker_ready, memory_order_acquire))
        CHECK(!atomic_load(&fault) && sched_yield() == 0);
      atomic_store_explicit(&target, thread, memory_order_release);
      baseline = snapshot(&baseline_waits);
      CHECK(baseline > 0);
      for (long i = 0; i < baseline; ++i)
        baseline_handles[i] = records[i].handle;
      atomic_store_explicit(&go, iteration + 1, memory_order_release);
      void *result = NULL;
      CHECK(pthread_join(thread, &result) == 0 &&
            result == (mode == 0 ? (void *)0x55 : PTHREAD_CANCELED));
      while (atomic_load_explicit(&sender_busy, memory_order_acquire))
        CHECK(sched_yield() == 0);
      if (mode != 3)
        ++expected_escapes;
      CHECK(!atomic_load(&fault) && atomic_load(&escapes) == expected_escapes &&
            atomic_load(&cleanups) == iteration + 1);
      CHECK(atomic_load(&returned) == (mode == 2 ? 1u : 0u));
      if (mode == 3) {
        struct stat status;
        CHECK(fstat(source, &status) == 0 && status.st_size == 8192);
      }
      probe = open(path, O_RDONLY);
      CHECK(probe == expected_fd && close(probe) == 0);
      ++iteration;
    }
    fprintf(stderr,
            "open-thread-exit: mode=%u cleanup/cancellation checks PASS\n",
            mode);
  }
  atomic_store_explicit(&stopping, 1, memory_order_release);
  CHECK(pthread_join(notifier, NULL) == 0 && !atomic_load(&fault));
  CHECK(close(source) == 0 && unlink(path) == 0);
  printf(
      "open-thread-exit: PASS 40 exit/cancel cases; pending-entry, unpublished "
      "reply, disabled cancellation and cleanup ownership\n");
  return 0;
}
