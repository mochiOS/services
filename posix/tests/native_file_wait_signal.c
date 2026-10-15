/* Observe an actual caller-owned admission position before sending a signal.
 * Qualify coverage only when the handler sees the original size unchanged;
 * post-commit delivery is NOT evidence of interrupting a pre-storage wait. */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr,                                                          \
              "file-wait-signal: FAIL line=%u errno=%d handler=%d: %s\n",      \
              __LINE__, errno, (int)handler_error, #x);                        \
      return 1;                                                                \
    }                                                                          \
  } while (0)
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal-safe handshake");
struct handle_info {
  uint32_t handle, reserved;
  uint64_t rights;
};
static int source, reader_fd;
static const char *replacement_path;
static char supplied_path[128];
static pthread_t target;
static unsigned baseline_waits;
static atomic_uint active, sent, reads;
static atomic_int stopping, ready, busy, sender_error, reader_error;
static volatile sig_atomic_t handler_error, qualified, operation_kind;

/* Caller-local metadata only; no Handle acquisition and no foreign PID/FD. */
static int wait_positions(void) {
  struct handle_info records[128];
  uint64_t number = 680; /* HandleTableRead */
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"((uintptr_t)records), "S"((uint64_t)128)
                   : "rcx", "r11", "memory");
  if ((int64_t)number < 0 || number > 128)
    return -1;
  int count = 0;
  for (unsigned i = 0; i < number; ++i) {
    if (records[i].reserved || !records[i].handle)
      return -1;
    if (records[i].rights == ((UINT64_C(1) << 63) | 16))
      ++count;
  }
  return count;
}

static void handler(int signal) {
  int previous = errno;
  unsigned epoch = atomic_load_explicit(&active, memory_order_acquire);
  if (signal != SIGUSR1)
    handler_error = 1;
  if (epoch && atomic_load_explicit(&sent, memory_order_acquire) == epoch) {
    if (wait_positions() != (int)baseline_waits) {
      handler_error = 2; /* C must never execute with the owned wait ticket. */
      return;
    }
    struct stat status;
    if (fstat(reader_fd, &status)) {
      handler_error = 3;
      return;
    }
    if (status.st_size == 8192) {
      if (operation_kind != 0) {
        strcpy(supplied_path, replacement_path);
        qualified = 1;
      } else if (close(source))
        handler_error = 4;
      else {
        int replacement = open(replacement_path, O_RDWR);
        if (replacement != source)
          handler_error = 5;
        else
          qualified = 1;
      }
    }
  }
  errno = previous;
}

static void *read_continuously(void *unused) {
  (void)unused;
  char bytes[4096];
  while (!atomic_load_explicit(&stopping, memory_order_acquire)) {
    if (pread(reader_fd, bytes, sizeof(bytes), 0) < 0) {
      atomic_store(&reader_error, errno);
      break;
    }
    atomic_fetch_add(&reads, 1);
  }
  return NULL;
}

static void *notify_waiter(void *unused) {
  (void)unused;
  int error = pthread_kill(target, 0);
  if (error)
    atomic_store(&sender_error, error);
  atomic_store_explicit(&ready, 1, memory_order_release);
  while (!atomic_load_explicit(&stopping, memory_order_acquire)) {
    unsigned epoch = atomic_load_explicit(&active, memory_order_acquire);
    if (!epoch || epoch == atomic_load_explicit(&sent, memory_order_acquire)) {
      sched_yield();
      continue;
    }
    atomic_store_explicit(&busy, 1, memory_order_release);
    int positions = wait_positions();
    if (positions < 0)
      atomic_store(&sender_error, EIO);
    if (positions > (int)baseline_waits &&
        atomic_load_explicit(&active, memory_order_acquire) == epoch) {
      atomic_store_explicit(&sent, epoch, memory_order_release);
      error = pthread_kill(target, SIGUSR1);
      if (error)
        atomic_store(&sender_error, error);
    }
    atomic_store_explicit(&busy, 0, memory_order_release);
  }
  return NULL;
}

int main(void) {
  fprintf(stderr, "file-wait-signal: starting observed waits and FD reuse\n");
  char original[] = "/tmp/file-wait-original-XXXXXX";
  char replacement[] = "/tmp/file-wait-replacement-XXXXXX";
  source = mkstemp(original);
  CHECK(source >= 0 && ftruncate(source, 8192) == 0);
  reader_fd = dup(source);
  CHECK(reader_fd >= 0);
  int other = mkstemp(replacement);
  CHECK(other >= 0 && ftruncate(other, 1234) == 0 && close(other) == 0);
  int expected_open_fd = other;
  replacement_path = replacement;
  target = pthread_self();
  struct sigaction action = {0};
  sigemptyset(&action.sa_mask);
  action.sa_handler = handler;
  CHECK(sigaction(SIGUSR1, &action, NULL) == 0 && raise(SIGUSR1) == 0);
  sigset_t blocked;
  sigemptyset(&blocked);
  sigaddset(&blocked, SIGUSR1);
  CHECK(pthread_sigmask(SIG_BLOCK, &blocked, NULL) == 0);
  pthread_t reader, sender;
  CHECK(pthread_create(&reader, NULL, read_continuously, NULL) == 0);
  CHECK(pthread_create(&sender, NULL, notify_waiter, NULL) == 0);
  while (!atomic_load_explicit(&ready, memory_order_acquire) ||
         !atomic_load(&reads))
    CHECK(!atomic_load(&reader_error) && sched_yield() == 0);
  int count = wait_positions();
  CHECK(count >= 0);
  baseline_waits = (unsigned)count;
  unsigned epoch = 0;
  for (unsigned kind = 0; kind < 3; ++kind) {
    operation_kind = kind;
    for (unsigned restart = 0; restart < 2; ++restart) {
      action.sa_flags = restart ? SA_RESTART : 0;
      CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
      unsigned successes = 0;
      for (unsigned attempt = 0; attempt < 256 && successes < 4; ++attempt) {
        CHECK(ftruncate(reader_fd, 8192) == 0);
        strcpy(supplied_path, original);
        qualified = 0;
        CHECK(pthread_sigmask(SIG_UNBLOCK, &blocked, NULL) == 0);
        atomic_store_explicit(&active, ++epoch, memory_order_release);
        errno = 0;
        int result = kind == 0   ? ftruncate(source, 5000)
                     : kind == 1 ? truncate(supplied_path, 5000)
                                 : open(supplied_path, O_RDWR | O_TRUNC);
        int operation_errno = errno;
        atomic_store_explicit(&active, 0, memory_order_release);
        CHECK(pthread_sigmask(SIG_BLOCK, &blocked, NULL) == 0);
        while (atomic_load_explicit(&busy, memory_order_acquire))
          CHECK(sched_yield() == 0);
        CHECK(!handler_error && !atomic_load(&sender_error) &&
              !atomic_load(&reader_error));
        /* Discard any delivery that lost the race with operation completion.
         * A fresh epoch cannot mistake that old signal for a new wait sample.
         */
        struct timespec zero = {0, 0};
        int pending;
        do {
          pending = sigtimedwait(&blocked, NULL, &zero);
        } while (pending == SIGUSR1);
        CHECK(pending == -1 && errno == EAGAIN);
        CHECK((kind == 2 ? result >= 0 : result == 0) ||
              (result == -1 && operation_errno == EINTR));
        if (!qualified) {
          if (kind == 2 && result >= 0)
            CHECK(close(result) == 0);
          continue;
        }
        if (kind != 0)
          CHECK(strcmp(supplied_path, replacement) == 0);
        struct stat old_status, new_status;
        CHECK(fstat(reader_fd, &old_status) == 0);
        other = open(replacement, O_RDONLY);
        CHECK(other == expected_open_fd + (kind == 2 && result >= 0));
        CHECK(fstat(other, &new_status) == 0 && close(other) == 0);
        CHECK(new_status.st_size == 1234);
        if (restart)
          CHECK((kind == 2 ? result >= 0 : result == 0) &&
                old_status.st_size == (kind == 2 ? 0 : 5000));
        else
          CHECK(result == -1 && operation_errno == EINTR &&
                old_status.st_size == 8192);
        CHECK(wait_positions() == (int)baseline_waits);
        if (kind == 2 && result >= 0) {
          struct stat opened_status;
          CHECK(result == expected_open_fd &&
                fstat(result, &opened_status) == 0);
          CHECK(opened_status.st_ino == old_status.st_ino &&
                opened_status.st_dev == old_status.st_dev);
          CHECK(close(result) == 0);
        }
        if (kind == 0) {
          CHECK(close(source) == 0);
          int reopened = open(original, O_RDWR);
          CHECK(reopened == source);
        }
        ++successes;
      }
      CHECK(successes == 4);
      fprintf(
          stderr,
          "file-wait-signal: operation=%u restart=%u four observed pre-storage "
          "interruptions PASS\n",
          kind, restart);
    }
  }
  atomic_store_explicit(&stopping, 1, memory_order_release);
  CHECK(pthread_join(sender, NULL) == 0 && pthread_join(reader, NULL) == 0);
  CHECK(!handler_error && !atomic_load(&sender_error) &&
        !atomic_load(&reader_error));
  CHECK(close(source) == 0 && close(reader_fd) == 0);
  CHECK(unlink(original) == 0 && unlink(replacement) == 0);
  printf("file-wait-signal: PASS all three mutations, EINTR, SA_RESTART, FD "
         "reuse, "
         "captured paths and no live "
         "ticket during C handlers (%u concurrent reads)\n",
         atomic_load(&reads));
  return 0;
}
