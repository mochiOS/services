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

#ifdef DIRECTORY_OPEN_TEST
#include <dirent.h>
#include <malloc.h>
#include <sys/stat.h>
static DIR *directory_streams[64];
static size_t directory_heap_baseline;
static int directory_setup_source(char *path) {
  // The dedicated fixture is fresh; no temporary-name helper is required.
  if (mkdir(path, 0700))
    return -1;
  return open(path, O_RDONLY | O_DIRECTORY);
}
static int directory_open_as_fd(const char *path, int flags) {
  (void)flags;
  DIR *stream = opendir(path);
  if (!stream)
    return -1;
  int fd = dirfd(stream);
  if (fd < 0 || fd >= 64) {
    closedir(stream);
    errno = EMFILE;
    return -1;
  }
  directory_streams[fd] = stream;
  return fd;
}
static int directory_close_fd(int fd) {
  if (fd >= 0 && fd < 64 && directory_streams[fd]) {
    DIR *stream = directory_streams[fd];
    directory_streams[fd] = NULL;
    return closedir(stream);
  }
  return close(fd);
}
#define mkstemp directory_setup_source
#define open directory_open_as_fd
#define close directory_close_fd
#define unlink rmdir
#endif

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "open-signal-escape: FAIL line=%u errno=%d: %s\n",       \
              __LINE__, errno, #x);                                            \
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
static uint32_t baseline_handles[4096];
static sigjmp_buf escape, nested_escape;
static atomic_int armed, stopping, ready, busy, sender_error;
static atomic_uint deliveries;
static volatile sig_atomic_t handler_error, escapes, nested_escapes,
    parents_preserved;
static pthread_t target;
static const char *test_path;
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

static int was_present(uint32_t handle) {
  for (long i = 0; i < baseline; ++i)
    if (baseline_handles[i] == handle)
      return 1;
  return 0;
}

static uint32_t unpublished_file(long count) {
  uint32_t found = 0;
  for (long i = 0; i < count; ++i) {
    if (was_present(records[i].handle))
      continue;
      /* READ | WRITE | SEEK: the observed extra reference must be a file, not
       * a lazy runtime allocation or another generic notification object. */
#ifdef DIRECTORY_OPEN_TEST
    if (found ||
        (records[i].rights & 131) != 1) /* Directory READ, no WRITE/SEEK. */
#else
    if (found || (records[i].rights & 131) != 131)
#endif
      return 0;
    found = records[i].handle;
  }
  return found;
}

static void handler(int signal) {
  int previous_errno = errno;
  atomic_fetch_add_explicit(&deliveries, 1, memory_order_release);
  if (signal != SIGUSR1 && signal != SIGUSR2)
    handler_error = 1;
  int phase = atomic_load_explicit(&armed, memory_order_acquire);
  if (phase) {
    unsigned waits;
    long count = snapshot(&waits);
    if (count < 0 || waits != baseline_waits) {
      /* In particular, libc must close its wait ticket BEFORE dispatching C. */
      handler_error = 2;
      atomic_store_explicit(&armed, 0, memory_order_release);
      siglongjmp(escape, 37);
    }
    if (signal == SIGUSR2 && phase == 2 && count == baseline + 2 &&
        fcntl(expected_fd, F_GETFD) == -1 && errno == EBADF &&
        fcntl(expected_fd + 1, F_GETFD) == -1 && errno == EBADF) {
      ++nested_escapes;
      atomic_store_explicit(&armed, 0, memory_order_release);
      // Retire only the operation started by SIGUSR1. Its interrupted parent
      // open must remain owned until the outer jump below.
      siglongjmp(nested_escape, 19);
    }
    if (signal == SIGUSR1 && phase == 1 && count == baseline + 1 &&
        fcntl(expected_fd, F_GETFD) == -1 && errno == EBADF) {
      uint32_t parent_handle = unpublished_file(count);
      if (!parent_handle) {
        errno = previous_errno;
        return;
      }
      int result = sigsetjmp(nested_escape, 1);
      if (!result) {
        atomic_store_explicit(&armed, 2, memory_order_release);
        for (unsigned attempt = 0; attempt < 256; ++attempt) {
          int opened = open(test_path, O_RDWR | O_TRUNC);
          if (opened != expected_fd + 1 || close(opened)) {
            handler_error = 3;
            break;
          }
        }
        handler_error = 4; /* No observed nested ownership boundary. */
      } else if (result != 19) {
        handler_error = 5;
      }
      // The inner reply and reservation are gone; the original reply and its
      // still-unpublished FD must be intact after the handler-local jump.
      if (snapshot(&waits) != baseline + 1 || waits != baseline_waits ||
          unpublished_file(baseline + 1) != parent_handle ||
          fcntl(expected_fd, F_GETFD) != -1 || errno != EBADF)
        handler_error = 6;
      else
        ++parents_preserved;
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
    int phase = atomic_load_explicit(&armed, memory_order_acquire);
    if (!phase) {
      sched_yield();
      continue;
    }
    atomic_store_explicit(&busy, 1, memory_order_release);
    unsigned before = atomic_load_explicit(&deliveries, memory_order_acquire);
    int signal = phase == 2 ? SIGUSR2 : SIGUSR1;
    error = pthread_kill(target, signal);
    if (error) {
      atomic_store(&sender_error, error);
      break;
    }
    // A duplicate SIGUSR1 can remain masked inside its handler. Do not wait
    // for that old notification after the handler requests nested SIGUSR2.
    while (atomic_load_explicit(&armed, memory_order_acquire) == phase &&
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
  test_path = path;
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
  CHECK(sigaction(SIGUSR2, &action, NULL) == 0);
  sigset_t empty;
  sigemptyset(&empty);
  CHECK(pthread_sigmask(SIG_SETMASK, &empty, NULL) == 0);
  pthread_t sender;
  CHECK(pthread_create(&sender, NULL, send_signals, NULL) == 0);
  while (!atomic_load_explicit(&ready, memory_order_acquire))
    CHECK(sched_yield() == 0);
  CHECK(atomic_load(&sender_error) == 0);
  CHECK(raise(SIGUSR1) ==
        0); /* Warm the signal path before counting Handles. */
  CHECK(raise(SIGUSR2) == 0);
  baseline = snapshot(&baseline_waits);
  CHECK(baseline > 0);
  for (long i = 0; i < baseline; ++i)
    baseline_handles[i] = records[i].handle;
#ifdef DIRECTORY_OPEN_TEST
  directory_heap_baseline = mallinfo().uordblks;
#endif
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
#ifdef DIRECTORY_OPEN_TEST
    CHECK(mallinfo().uordblks == directory_heap_baseline);
#endif
    for (long i = 0; i < baseline; ++i)
      CHECK(was_present(records[i].handle));
    CHECK(fcntl(expected_fd, F_GETFD) == -1 && errno == EBADF);
    probe = open(path, O_RDONLY);
    CHECK(probe == expected_fd && close(probe) == 0);
  }
  atomic_store_explicit(&stopping, 1, memory_order_release);
  CHECK(pthread_join(sender, NULL) == 0);
  CHECK(escapes == 16 && nested_escapes == 16 && parents_preserved == 16 &&
        !handler_error && !atomic_load(&sender_error));
  CHECK(close(source) == 0 && unlink(path) == 0);
  printf(
      "open-signal-escape: PASS %d outer escapes, %d reentrant open escapes, "
      "%d preserved parents; Handles and FD reservations reclaimed\n",
      (int)escapes, (int)nested_escapes, (int)parents_preserved);
  return 0;
}
