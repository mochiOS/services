/* Cancel only after observing a caller-owned admission position. Completion
 * races are permitted but do not count as pre-storage cancellation coverage. */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
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
              "open-cancel-wait: FAIL line=%u errno=%d fault=%d: %s\n",        \
              __LINE__, errno, atomic_load(&fault), #x);                       \
      return 1;                                                                \
    }                                                                          \
  } while (0)
struct handle_info {
  uint32_t handle, reserved;
  uint64_t rights;
};
_Static_assert(sizeof(struct handle_info) == 16, "native Handle metadata ABI");
static struct handle_info during[128];
static long during_count;
static unsigned during_waits, disabled;
static int source, reader_fd, expected_fd;
static const char *filename;
static atomic_int fault, stopping, ready, go, done, returned, selected,
    qualified, cleaned;
static atomic_uint reads;

static long snapshot(struct handle_info *output, unsigned *waits) {
  uint64_t number = 680; /* HandleTableRead: no acquisition or foreign PID. */
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"((uintptr_t)output), "S"((uint64_t)128)
                   : "rcx", "r11", "memory");
  if ((int64_t)number < 0 || number > 128)
    return -1;
  *waits = 0;
  for (unsigned i = 0; i < number; ++i) {
    if (!output[i].handle || output[i].reserved)
      return -1;
    if (output[i].rights == ((UINT64_C(1) << 63) | 16))
      ++*waits;
  }
  return (long)number;
}

static int same_set(const struct handle_info *left, long left_count,
                    const struct handle_info *right, long right_count) {
  if (left_count != right_count || left_count < 0)
    return 0;
  for (long i = 0; i < left_count; ++i) {
    int found = 0;
    for (long j = 0; j < right_count; ++j)
      if (left[i].handle == right[j].handle &&
          left[i].rights == right[j].rights)
        found = 1;
    if (!found)
      return 0;
  }
  return 1;
}

static void cleanup(void *unused) {
  (void)unused;
  struct handle_info now[128];
  unsigned waits;
  long count = snapshot(now, &waits);
  if (!same_set(now, count, during, during_count) || waits != during_waits) {
    atomic_store(&fault, 1);
    return;
  }
  if (fcntl(expected_fd, F_GETFD) != -1 || errno != EBADF) {
    atomic_store(&fault, 2);
    return;
  }
  struct stat status;
  if (fstat(source, &status)) {
    atomic_store(&fault, 3);
    return;
  }
  if (atomic_load(&selected) &&
      (disabled ? atomic_load(&returned) && status.st_size == 0
                : !atomic_load(&returned) && status.st_size == 8192))
    atomic_store(&qualified, 1);
  int fd = open(filename, O_RDONLY);
  if (fd != expected_fd || close(fd)) {
    atomic_store(&fault, 4);
    return;
  }
  atomic_store(&cleaned, 1);
}

static void *worker(void *unused) {
  (void)unused;
  int fd = open(filename, O_RDONLY);
  if (fd != expected_fd || close(fd) ||
      (disabled && pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL))) {
    atomic_store(&fault, 5);
    return (void *)1;
  }
  pthread_cleanup_push(cleanup, NULL);
  atomic_store_explicit(&ready, 1, memory_order_release);
  while (!atomic_load_explicit(&go, memory_order_acquire))
    sched_yield();
  fd = open(filename, O_RDWR | O_TRUNC);
  atomic_store(&returned, 1);
  if (fd != expected_fd)
    atomic_store(&fault, 6);
  else {
    // Returning a committed FD is a valid race outcome. Release it before any
    // later cancellation point, including a future cancellable public close.
    int previous;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) ||
        close(fd) || pthread_setcancelstate(previous, NULL))
      atomic_store(&fault, 7);
  }
  atomic_store_explicit(&done, 1, memory_order_release);
  if (disabled) {
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL))
      atomic_store(&fault, 8);
    pthread_testcancel();
  }
  pthread_cleanup_pop(0);
  return NULL;
}

static void *reader(void *unused) {
  (void)unused;
  char bytes[4096];
  while (!atomic_load_explicit(&stopping, memory_order_acquire)) {
    if (pread(reader_fd, bytes, sizeof(bytes), 0) < 0) {
      atomic_store(&fault, 9);
      break;
    }
    atomic_fetch_add(&reads, 1);
  }
  return NULL;
}

int main(void) {
  fprintf(stderr, "open-cancel-wait: starting real admission cancellation\n");
  char path[] = "/tmp/open-cancel-wait-XXXXXX";
  source = mkstemp(path);
  CHECK(source >= 0 && ftruncate(source, 8192) == 0);
  filename = path;
  reader_fd = dup(source);
  CHECK(reader_fd >= 0);
  int probe = open(filename, O_RDONLY);
  CHECK(probe >= 0 && close(probe) == 0);
  expected_fd = probe;
  pthread_t reading;
  CHECK(pthread_create(&reading, NULL, reader, NULL) == 0);
  while (!atomic_load(&reads))
    CHECK(!atomic_load(&fault) && sched_yield() == 0);
  unsigned observations = 0, completed = 0;
  for (disabled = 0; disabled < 2; ++disabled) {
    unsigned successes = 0;
    for (unsigned trial = 0; trial < 128 && successes < 4; ++trial) {
      CHECK(ftruncate(source, 8192) == 0);
      struct handle_info before[128], now[128];
      unsigned waits;
      long before_count = snapshot(before, &waits);
      CHECK(before_count > 0);
      atomic_store(&ready, 0);
      atomic_store(&go, 0);
      atomic_store(&done, 0);
      atomic_store(&returned, 0);
      atomic_store(&selected, 0);
      atomic_store(&qualified, 0);
      atomic_store(&cleaned, 0);
      pthread_t thread;
      CHECK(pthread_create(&thread, NULL, worker, NULL) == 0);
      while (!atomic_load_explicit(&ready, memory_order_acquire))
        CHECK(!atomic_load(&fault) && sched_yield() == 0);
      during_count = snapshot(during, &during_waits);
      CHECK(during_count > 0);
      atomic_store_explicit(&go, 1, memory_order_release);
      while (!atomic_load_explicit(&done, memory_order_acquire)) {
        CHECK(!atomic_load(&fault));
        long count = snapshot(now, &waits);
        CHECK(count > 0);
        if (waits > during_waits) {
          ++observations;
          atomic_store(&selected, 1);
          CHECK(pthread_cancel(thread) == 0);
          // Cleanup may now inspect metadata itself: never race its buffer or
          // assert on a half-retired operation. Join before observing again.
          break;
        }
        CHECK(sched_yield() == 0);
      }
      void *result = NULL;
      CHECK(pthread_join(thread, &result) == 0);
      CHECK(!atomic_load(&fault));
      if (result == PTHREAD_CANCELED) {
        CHECK(atomic_load(&selected) && atomic_load(&cleaned));
        if (atomic_load(&qualified))
          ++successes;
      } else {
        CHECK(result == NULL && atomic_load(&returned));
        ++completed;
      }
      long count = snapshot(now, &waits);
      CHECK(same_set(now, count, before, before_count));
      probe = open(filename, O_RDONLY);
      CHECK(probe == expected_fd && close(probe) == 0);
    }
    CHECK(successes == 4);
    fprintf(stderr, "open-cancel-wait: disabled=%u four observed cases PASS\n",
            disabled);
  }
  atomic_store_explicit(&stopping, 1, memory_order_release);
  CHECK(pthread_join(reading, NULL) == 0 && !atomic_load(&fault));
  CHECK(close(source) == 0 && close(reader_fd) == 0 && unlink(path) == 0);
  printf(
      "open-cancel-wait: PASS pre-storage cancellation, disabled completion, "
      "exact Handle sets and FD reuse (%u positions, %u completion races, "
      "%u unthrottled reads)\n",
      observations, completed, atomic_load(&reads));
  return 0;
}
