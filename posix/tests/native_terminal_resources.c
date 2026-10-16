#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <pty.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static unsigned operation, outcome;
static int master, operation_fd, replacement;
static uint32_t operation_handle;
static struct termios attributes;
static atomic_uint observer;
static volatile sig_atomic_t qualified, handler_error;
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
              "terminal-resources: FAIL op=%u outcome=%u line=%u errno=%d "    \
              "handler=%d: %s\n",                                              \
              operation, outcome, __LINE__, errno, (int)handler_error, #x);    \
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
  if ((uint64_t)native(664, operation_handle, 0, 0) >= (uint64_t)-4095)
    handler_error = 2;
  else
    qualified = 1;
  if (dup(replacement) != operation_fd)
    handler_error = 3;
  if (outcome == 1)
    siglongjmp(destination, 37);
  if (outcome == 2)
    pthread_exit((void *)0x55);
  char byte = 0;
  if (read(master, &byte, 1) != 1 || byte != 'q')
    handler_error = 4;
  /* The in-progress attribute change must use the earlier snapshot. */
  attributes.c_lflag |= UINT32_C(0x80000000);
}
static void *run_operation(void *unused) {
  (void)unused;
  int jumped = sigsetjmp(destination, 1);
  if (jumped)
    return jumped == 37 ? (void *)0x37 : (void *)1;
  int64_t handle = native(656, 0, 0, 0);
  if (handle <= 0)
    return (void *)2;
  atomic_store_explicit(&observer, (unsigned)handle, memory_order_release);
  int result =
      operation == 0
          ? tcdrain(operation_fd)
          : tcsetattr(operation_fd, operation == 1 ? TCSADRAIN : TCSAFLUSH,
                      &attributes);
  return result == 0 ? NULL : (void *)3;
}
static void *warm(void *argument) { return argument; }
static int blocked_cases(void) {
  struct sigaction action = {0};
  action.sa_handler = interrupted;
  action.sa_flags = SA_RESTART;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
  pthread_t thread;
  void *result;
  CHECK(pthread_create(&thread, NULL, warm, NULL) == 0);
  CHECK(pthread_join(thread, &result) == 0);
  for (operation = 0; operation < 3; ++operation) {
    for (outcome = 0; outcome < (operation == 0 ? 4u : 3u); ++outcome) {
      int64_t start = native(680, 0, 0, 0);
      int slave, pipefd[2];
      CHECK(openpty(&master, &slave, NULL, NULL, NULL) == 0);
      CHECK(tcgetattr(slave, &attributes) == 0);
      operation_fd = duplicate_observed(slave);
      CHECK(operation_fd >= 0 && close(slave) == 0);
      CHECK(pipe(pipefd) == 0);
      replacement = pipefd[1];
      CHECK(write(operation_fd, "q", 1) == 1);
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
              /* Runtime signal-delivery reference plus the explicit observer. */
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
      CHECK(!handler_error && (outcome == 3 || qualified));
      CHECK(native(626, handle, 0, 0) == 0);
      CHECK((uint64_t)native(664, operation_handle, 0, 0) >= (uint64_t)-4095 ||
            outcome == 3);
      CHECK(close(operation_fd) == 0 && close(master) == 0);
      CHECK(close(pipefd[0]) == 0 && close(pipefd[1]) == 0);
      CHECK(native(680, 0, 0, 0) == start);
      fprintf(stderr, "terminal-resources: op=%u outcome=%u PASS\n", operation,
              outcome);
    }
  }
  return 0;
}
static void bad_copy(int signal) {
  if (signal != SIGSEGV)
    _exit(91);
  if (close(operation_fd))
    _exit(92);
  siglongjmp(destination, 37);
}
int main(void) {
  if (blocked_cases())
    return 1;
  struct sigaction action = {0};
  action.sa_handler = bad_copy;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  for (operation = 3; operation < 7; ++operation) {
    int64_t baseline = native(680, 0, 0, 0);
    int slave;
    CHECK(openpty(&master, &slave, NULL, NULL, NULL) == 0);
    operation_fd = slave;
    void *page =
        mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(page != MAP_FAILED);
    int jumped = sigsetjmp(destination, 1);
    if (!jumped) {
      switch (operation) {
      case 3:
        tcgetattr(operation_fd, page);
        break;
      case 4:
        tcsetattr(operation_fd, TCSANOW, page);
        break;
      case 5:
        tcgetwinsize(operation_fd, page);
        break;
      case 6:
        tcsetwinsize(operation_fd, page);
        break;
      }
      CHECK(0);
    }
    CHECK(jumped == 37 && close(master) == 0 && munmap(page, 4096) == 0);
    CHECK(native(680, 0, 0, 0) == baseline);
    fprintf(stderr, "terminal-resources: fault op=%u PASS\n", operation);
  }
  puts("terminal-resources: PASS 10 blocked return/jump/exit/cancel and 4 "
       "caller-copy fault cases");
  return 0;
}
