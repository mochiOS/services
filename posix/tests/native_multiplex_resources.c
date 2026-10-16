#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
static unsigned api, kind, outcome;
static int operation_fd, peer, replacement;
static uint32_t operation_handle;
static atomic_uint observer;
static volatile sig_atomic_t qualified, handler_error, faulted;
static sigjmp_buf destination;
struct handle_record {
  uint32_t handle, reserved;
  uint64_t rights;
};
struct thread_record {
  uint64_t thread, process;
  uint32_t state, reserved;
};
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr,                                                          \
              "multiplex-resources: FAIL api=%u kind=%u outcome=%u line=%u "   \
              "errno=%d handler=%d: %s\n",                                     \
              api, kind, outcome, __LINE__, errno, (int)handler_error, #x);    \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static int64_t native(uint64_t number, uint64_t a, uint64_t b, uint64_t c) {
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(a), "S"(b), "d"(c)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
static int duplicate_observed(int source) {
  struct handle_record old[128], current[128];
  int before = native(680, (uintptr_t)old, 128, 0);
  int fd = dup(source);
  int after = native(680, (uintptr_t)current, 128, 0);
  if (fd < 0 || before <= 0 || after != before + 1)
    return -1;
  operation_handle = 0;
  for (int i = 0; i < after; ++i) {
    int found = 0;
    for (int j = 0; j < before; ++j)
      found |= current[i].handle == old[j].handle;
    if (!found)
      operation_handle = current[i].handle;
  }
  return operation_handle ? fd : -1;
}
static void interrupted(int signal) {
  if (signal != SIGUSR1)
    return;
  if (close(operation_fd))
    handler_error = 1;
  if ((uint64_t)native(664, operation_handle, 0, 0) < (uint64_t)-4095)
    qualified = 1;
  if (dup(replacement) != operation_fd)
    handler_error = 3;
  if (api >= 2 && qualified) {
    sigset_t mask;
    if (pthread_sigmask(SIG_SETMASK, NULL, &mask) ||
        sigismember(&mask, SIGUSR2) != 1)
      handler_error = 4;
  }
  if (outcome == 1)
    siglongjmp(destination, 37);
  if (outcome == 2)
    pthread_exit((void *)0x55);
  if (write(peer, "q", 1) != 1)
    handler_error = 5;
}
static int invoke(fd_set *readset, fd_set *writeset, struct pollfd *items,
                  nfds_t count, int immediate) {
  struct timeval zero = {0};
  struct timespec instant = {0};
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGUSR2);
  switch (api) {
  case 0:
    return select(operation_fd + 1, readset, writeset, NULL,
                  immediate ? &zero : NULL);
  case 1:
    return poll(items, count, immediate ? 0 : -1);
  case 2:
    return pselect(operation_fd + 1, readset, writeset, NULL,
                   immediate ? &instant : NULL, &mask);
  default:
    return ppoll(items, count, immediate ? &instant : NULL, &mask);
  }
}
static void *run_operation(void *unused) {
  (void)unused;
  int jumped = sigsetjmp(destination, 1);
  if (jumped)
    return jumped == 37 ? (void *)0x37 : (void *)1;
  fd_set readset;
  FD_ZERO(&readset);
  FD_SET(operation_fd, &readset);
  struct pollfd item = {operation_fd, POLLIN, 0};
  int64_t handle = native(656, 0, 0, 0);
  if (handle <= 0)
    return (void *)2;
  atomic_store_explicit(&observer, (unsigned)handle, memory_order_release);
  int result = invoke(&readset, NULL, &item, 1, 0);
  if (result != -1 || errno != EINTR)
    return (void *)3;
  sigset_t restored;
  if (pthread_sigmask(SIG_SETMASK, NULL, &restored) ||
      sigismember(&restored, SIGUSR2))
    return (void *)4;
  return NULL;
}
static void *warm(void *value) { return value; }
static int blocked_cases(void) {
  struct sigaction action = {0};
  action.sa_handler = interrupted;
  action.sa_flags = SA_RESTART;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
  pthread_t thread;
  void *result;
  CHECK(pthread_create(&thread, NULL, warm, NULL) == 0 &&
        pthread_join(thread, &result) == 0);
  for (api = 0; api < 4; ++api)
    for (kind = 0; kind < 2; ++kind)
      for (outcome = 0; outcome < 4; ++outcome) {
        unsigned qualification_attempt = 0;
      retry_case:;
        int64_t start = native(680, 0, 0, 0);
        int pair[2], extra[2];
        CHECK((kind ? socketpair(AF_UNIX, SOCK_STREAM, 0, pair) : pipe(pair)) ==
              0);
        operation_fd = duplicate_observed(pair[0]);
        peer = pair[1];
        CHECK(operation_fd >= 0 && close(pair[0]) == 0 && pipe(extra) == 0);
        replacement = extra[1];
        int64_t baseline = native(680, 0, 0, 0);
        qualified = handler_error = 0;
        atomic_store(&observer, 0);
        CHECK(pthread_create(&thread, NULL, run_operation, NULL) == 0);
        unsigned handle = 0, attempt;
        for (attempt = 0; attempt < 5000; ++attempt) {
          handle = atomic_load_explicit(&observer, memory_order_acquire);
          struct thread_record status = {0};
          if (handle) {
            CHECK(native(658, handle, (uintptr_t)&status, 0) == 0 &&
                  status.state != 5);
            if ((status.state == 3 || status.state == 4) &&
                native(680, 0, 0, 0) == baseline + 2) {
              struct timespec stable = {0, 10000000};
              CHECK(nanosleep(&stable, NULL) == 0);
              CHECK(native(658, handle, (uintptr_t)&status, 0) == 0);
              if (status.state == 3 || status.state == 4)
                break;
            }
          }
          struct timespec delay = {0, 1000000};
          CHECK(nanosleep(&delay, NULL) == 0);
        }
        CHECK(attempt < 5000);
        CHECK(outcome == 3 ? pthread_cancel(thread) == 0
                           : pthread_kill(thread, SIGUSR1) == 0);
        CHECK(pthread_join(thread, &result) == 0);
        CHECK(result == (outcome == 0   ? NULL
                         : outcome == 1 ? (void *)0x37
                         : outcome == 2 ? (void *)0x55
                                        : PTHREAD_CANCELED));
        CHECK(!handler_error);
        CHECK(native(626, handle, 0, 0) == 0);
        CHECK(close(operation_fd) == 0 && close(peer) == 0 &&
              close(extra[0]) == 0 && close(extra[1]) == 0);
        CHECK(native(680, 0, 0, 0) == start);
        // A blocked mask RPC or a completed EINTR can also deliver the handler.
        // Only accept a run whose closed FD remained pinned by the active wait.
        if (outcome != 3 && !qualified) {
          CHECK(++qualification_attempt < 8);
          fprintf(stderr,
                  "multiplex-resources: retry outside active wait api=%u "
                  "kind=%u outcome=%u\n",
                  api, kind, outcome);
          goto retry_case;
        }
        fprintf(stderr, "multiplex-resources: api=%u kind=%u outcome=%u PASS\n",
                api, kind, outcome);
      }
  return 0;
}
static void bad_copy(int signal) {
  if (signal != SIGSEGV)
    _exit(91);
  if (close(operation_fd))
    _exit(92);
  faulted = 1;
  siglongjmp(destination, 37);
}
int main(void) {
  if (blocked_cases())
    return 1;
  struct sigaction action = {0};
  action.sa_handler = bad_copy;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  for (api = 0; api < 4; ++api)
    for (outcome = 0; outcome < 4; ++outcome) {
      int64_t baseline = native(680, 0, 0, 0);
      int pair[2];
      CHECK(pipe(pair) == 0);
      operation_fd = pair[0];
      unsigned char *page = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      CHECK(page != MAP_FAILED);
      fd_set *readset = (fd_set *)page;
      fd_set *volatile writeset = outcome == 3 ? (fd_set *)(page + 4096) : NULL;
      struct pollfd *volatile items =
          (struct pollfd *)(outcome == 3 ? page + 4096 - sizeof(struct pollfd)
                                         : page);
      if (api & 1) {
        items[0] = (struct pollfd){operation_fd, POLLIN, 0};
        if (outcome == 3)
          items[1] = items[0];
      } else {
        FD_ZERO(readset);
        FD_SET(operation_fd, readset);
      }
      CHECK(write(pair[1], "q", 1) == 1);
      if (outcome == 1 || outcome == 2)
        CHECK(mprotect(page, 4096, outcome == 1 ? PROT_NONE : PROT_READ) == 0);
      if (outcome == 3)
        CHECK(mprotect(page + 4096, 4096, PROT_READ) == 0);
      faulted = 0;
      int jumped = sigsetjmp(destination, 1);
      if (!jumped) {
        CHECK(invoke(readset, writeset, items, outcome == 3 ? 2 : 1, 1) == 1 &&
              outcome == 0);
        CHECK(close(operation_fd) == 0);
      } else
        CHECK(jumped == 37 && outcome != 0 && faulted);
      CHECK(faulted == (outcome != 0));
      CHECK(close(pair[1]) == 0 && munmap(page, 8192) == 0);
      CHECK(native(680, 0, 0, 0) == baseline);
      fprintf(stderr, "multiplex-resources: copy api=%u outcome=%u PASS\n", api,
              outcome);
    }
  puts("multiplex-resources: PASS 32 blocked return/jump/exit/cancel and 16 "
       "input/output copy cases");
  return 0;
}
