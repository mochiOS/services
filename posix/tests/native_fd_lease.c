#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      printf("fd-lease: FAIL line=%d errno=%d\n", __LINE__, errno);            \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static pthread_t lease_reader;
static int lease_target, lease_replacement, lease_writer;
static volatile sig_atomic_t lease_handler_error, lease_handled;
static atomic_int lease_entering;

static int64_t lease_handle_count(void) {
  uint64_t number = 680;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(0), "S"(0)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}

static void lease_replace(int signal) {
  (void)signal;
  int saved = errno;
  if (close(lease_target) ||
      dup2(lease_replacement, lease_target) != lease_target ||
      write(lease_writer, "A", 1) != 1)
    lease_handler_error = 1;
  lease_handled = 1;
  errno = saved;
}

static void *lease_interrupt(void *argument) {
  while (!atomic_load(&lease_entering))
    sched_yield();
  // The deterministic pre-dispatch race is tested on the host against the
  // actual guard. Here allow native read/poll to enter its interruptible wait.
  struct timespec delay = {0, 50000000};
  nanosleep(&delay, NULL);
  // poll is interrupted even by SA_RESTART signals. Exercise concurrent FD
  // replacement without a signal in that case, rather than hiding EINTR.
  if (argument != NULL) {
    lease_replace(0);
    return NULL;
  }
  int error = pthread_kill(lease_reader, SIGUSR1);
  if (error) {
    lease_handler_error = 1;
    write(lease_writer, "A", 1); // Never leave a failed test's reader stranded.
  }
  return NULL;
}

static void *lease_cancel_read(void *argument) {
  int fd = (int)(intptr_t)argument;
  atomic_store(&lease_entering, 1);
  char byte;
  read(fd, &byte, 1);
  return (void *)(intptr_t)1;
}

int main(void) {
  int64_t baseline = lease_handle_count();
  CHECK(baseline > 0);
  struct sigaction action = {0}, old_action, ignore = {0}, old_pipe;
  action.sa_handler = lease_replace;
  action.sa_flags = SA_RESTART;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGUSR1, &action, &old_action) == 0);
  ignore.sa_handler = SIG_IGN;
  sigemptyset(&ignore.sa_mask);
  CHECK(sigaction(SIGPIPE, &ignore, &old_pipe) == 0);
  lease_reader = pthread_self();
  for (unsigned mode = 0; mode < 2; ++mode) {
    int original[2], replacement[2];
    CHECK(pipe(original) == 0 && pipe(replacement) == 0);
    lease_target = original[0];
    lease_writer = original[1];
    lease_replacement = replacement[0];
    CHECK(write(replacement[1], "B", 1) == 1);
    lease_handler_error = lease_handled = 0;
    atomic_store(&lease_entering, 0);
    pthread_t sender;
    CHECK(pthread_create(&sender, NULL, lease_interrupt,
                         (void *)(uintptr_t)mode) == 0);
    atomic_store(&lease_entering, 1);
    if (mode == 0) {
      char byte;
      CHECK(read(lease_target, &byte, 1) == 1 && byte == 'A');
    } else {
      struct pollfd descriptor = {lease_target, POLLIN, 0};
      CHECK(poll(&descriptor, 1, 2000) == 1 &&
            (descriptor.revents & POLLIN) != 0 &&
            (descriptor.revents & POLLNVAL) == 0);
    }
    CHECK(pthread_join(sender, NULL) == 0);
    CHECK(lease_handled && !lease_handler_error);
    char byte;
    CHECK(read(lease_target, &byte, 1) == 1 && byte == 'B');
    CHECK(close(lease_target) == 0 && close(original[1]) == 0 &&
          close(replacement[0]) == 0 && close(replacement[1]) == 0);
    CHECK(lease_handle_count() == baseline);
  }
  int pair[2];
  CHECK(pipe(pair) == 0);
  atomic_store(&lease_entering, 0);
  pthread_t reader;
  CHECK(pthread_create(&reader, NULL, lease_cancel_read,
                       (void *)(intptr_t)pair[0]) == 0);
  while (!atomic_load(&lease_entering))
    sched_yield();
  struct timespec delay = {0, 50000000};
  CHECK(nanosleep(&delay, NULL) == 0);
  CHECK(pthread_cancel(reader) == 0);
  void *result;
  CHECK(pthread_join(reader, &result) == 0 && result == PTHREAD_CANCELED);
  CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
  CHECK(lease_handle_count() == baseline);
  CHECK(sigaction(SIGUSR1, &old_action, NULL) == 0 &&
        sigaction(SIGPIPE, &old_pipe, NULL) == 0);
  puts("fd-lease: PASS restarted read and poll retain original objects across "
       "signal-handler/concurrent close/dup2; replacement stays independent; "
       "cancellation "
       "releases pins without Handle leaks");
  return 0;
}
