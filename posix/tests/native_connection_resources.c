#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static unsigned accepting, outcome;
static int listener, client, replacement, operation_fd;
static uint32_t operation_handle;
static struct sockaddr_un destination;
static socklen_t destination_length;
static atomic_uint observer;
static volatile sig_atomic_t qualified, handler_error;
static sigjmp_buf escape;
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
              "connection-resources: FAIL accept=%u outcome=%u line=%u "       \
              "errno=%d handler=%d: %s\n",                                     \
              accepting, outcome, __LINE__, errno, (int)handler_error, #x);    \
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
static int create_observed(uint32_t *label) {
  struct handle_record old[128], current[128];
  int before = native(680, (uintptr_t)old, 128, 0);
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  int after = native(680, (uintptr_t)current, 128, 0);
  if (fd < 0 || before <= 0 || after != before + 1)
    return -1;
  *label = 0;
  for (int i = 0; i < after; ++i) {
    int found = 0;
    for (int j = 0; j < before; ++j)
      found |= current[i].handle == old[j].handle;
    if (!found)
      *label = current[i].handle;
  }
  return *label ? fd : -1;
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
    siglongjmp(escape, 37);
  if (outcome == 2)
    pthread_exit((void *)0x55);
  if (accepting) {
    if (connect(client, (struct sockaddr *)&destination, destination_length))
      handler_error = 4;
  } else {
    int accepted = accept(listener, NULL, NULL);
    if (accepted < 0 || close(accepted))
      handler_error = 5;
  }
}
static void *run_operation(void *unused) {
  (void)unused;
  int jumped = sigsetjmp(escape, 1);
  if (jumped)
    return jumped == 37 ? (void *)0x37 : (void *)1;
  int64_t handle = native(656, 0, 0, 0);
  if (handle <= 0)
    return (void *)2;
  atomic_store_explicit(&observer, (unsigned)handle, memory_order_release);
  if (!accepting)
    return connect(operation_fd, (struct sockaddr *)&destination,
                   destination_length) == 0
               ? NULL
               : (void *)3;
  int accepted =
      accept4(operation_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
  if (accepted < 0)
    return (void *)4;
  int valid = (fcntl(accepted, F_GETFL) & O_NONBLOCK) &&
              (fcntl(accepted, F_GETFD) & FD_CLOEXEC) &&
              write(accepted, "q", 1) == 1;
  return close(accepted) == 0 && valid ? NULL : (void *)5;
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
  for (accepting = 0; accepting < 2; ++accepting) {
    for (outcome = 0; outcome < 4; ++outcome) {
      memset(&destination, 0, sizeof(destination));
      destination.sun_family = AF_UNIX;
      snprintf(destination.sun_path, sizeof(destination.sun_path),
               "/tmp/connection-scope-%d-%u-%u", (int)getpid(), accepting,
               outcome);
      destination_length = 2 + strlen(destination.sun_path) + 1;
      CHECK(unlink(destination.sun_path) == 0 || errno == ENOENT);
      int64_t start = native(680, 0, 0, 0);
      uint32_t listener_handle, client_handle;
      listener = create_observed(&listener_handle);
      CHECK(listener >= 0);
      CHECK(bind(listener, (struct sockaddr *)&destination,
                 destination_length) == 0);
      CHECK(listen(listener, 1) == 0);
      int first = -1;
      if (!accepting) {
        first = socket(AF_UNIX, SOCK_STREAM, 0);
        CHECK(first >= 0 && connect(first, (struct sockaddr *)&destination,
                                    destination_length) == 0);
      }
      client = create_observed(&client_handle);
      replacement = socket(AF_UNIX, SOCK_STREAM, 0);
      CHECK(client >= 0 && replacement >= 0);
      int alias = accepting ? dup(listener) : -1;
      CHECK(!accepting || alias >= 0);
      operation_fd = accepting ? listener : client;
      operation_handle = accepting ? listener_handle : client_handle;
      int64_t baseline = native(680, 0, 0, 0);
      qualified = handler_error = 0;
      atomic_store(&observer, 0);
      CHECK(pthread_create(&thread, NULL, run_operation, NULL) == 0);
      unsigned handle = 0, attempt;
      for (attempt = 0; attempt < 5000; ++attempt) {
        handle = atomic_load_explicit(&observer, memory_order_acquire);
        struct thread_record status = {0};
        if (handle) {
          CHECK(native(658, handle, (uintptr_t)&status, 0) == 0);
          CHECK(status.state != 5);
          if ((status.state == 3 || status.state == 4) &&
              native(680, 0, 0, 0) == baseline + (accepting ? 2 : 3))
            break;
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
      if (accepting && outcome == 0) {
        char byte = 0;
        CHECK(read(client, &byte, 1) == 1 && byte == 'q');
      }
      if (!accepting) {
        if (outcome != 0) {
          int accepted = accept(listener, NULL, NULL);
          CHECK(accepted >= 0 && close(accepted) == 0);
        }
        CHECK(fcntl(listener, F_SETFL, O_NONBLOCK) == 0);
        int completed = accept(listener, NULL, NULL);
        if (outcome == 0)
          CHECK(completed >= 0 && close(completed) == 0);
        else
          CHECK(completed == -1 && errno == EAGAIN);
        CHECK(close(first) == 0);
      }
      CHECK(close(listener) == 0 && close(client) == 0 &&
            close(replacement) == 0);
      if (accepting)
        CHECK(close(alias) == 0);
      CHECK(unlink(destination.sun_path) == 0);
      CHECK(native(680, 0, 0, 0) == start);
      fprintf(stderr, "connection-resources: accept=%u outcome=%u PASS\n",
              accepting, outcome);
    }
  }
  return 0;
}

static volatile sig_atomic_t output_fault;
static sigjmp_buf output_escape;
static struct sockaddr *bad_address;
static socklen_t *bad_length;
static void bad_output(int signal) {
  if (signal != SIGSEGV)
    _exit(91);
  output_fault = 1;
  int64_t baseline = native(680, 0, 0, 0);
  int nested_client = -1;
  if (outcome == 1 || outcome == 2) {
    nested_client = socket(AF_UNIX, SOCK_STREAM, 0);
    if (nested_client < 0 || connect(nested_client, (struct sockaddr *)&destination,
                                     destination_length))
      _exit(92);
  }
  if (accept4(listener, bad_address, bad_length, SOCK_NONBLOCK | SOCK_CLOEXEC) != -1 ||
      errno != EFAULT)
    _exit(93);
  if ((nested_client >= 0 && close(nested_client)) ||
      native(680, 0, 0, 0) != baseline)
    _exit(94);
  siglongjmp(output_escape, 37);
}
int main(void) {
  if (blocked_cases())
    return 1;
  struct sigaction action = {0};
  action.sa_handler = bad_output;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  for (outcome = 0; outcome < 8; ++outcome) {
    snprintf(destination.sun_path, sizeof(destination.sun_path),
             "/tmp/accept-output-%d-%u", (int)getpid(), outcome);
    destination_length = 2 + strlen(destination.sun_path) + 1;
    CHECK(unlink(destination.sun_path) == 0 || errno == ENOENT);
    int64_t start = native(680, 0, 0, 0);
    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    client = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(listener >= 0 && client >= 0);
    CHECK(bind(listener, (struct sockaddr *)&destination, destination_length) ==
              0 &&
          listen(listener, 1) == 0 &&
          connect(client, (struct sockaddr *)&destination,
                  destination_length) == 0);
    unsigned char *page = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(page != MAP_FAILED);
    memset(page, 0xa5, 4096);
    socklen_t *length = (socklen_t *)(page + 4096);
    *length = outcome == 5 ? 0 : outcome == 6 ? 1 : 110;
    int expected = dup(listener);
    CHECK(expected >= 0 && close(expected) == 0);
    int64_t baseline = native(680, 0, 0, 0);
    if (outcome == 1 || outcome == 2 || outcome == 5)
      CHECK(mprotect(page + (outcome == 2 ? 4096 : 0), 4096, PROT_READ) == 0);
    if (outcome == 3 || outcome == 7)
      CHECK(mprotect(page + 4096, 4096, PROT_NONE) == 0);
    bad_address = outcome == 4 ? NULL : (struct sockaddr *)(page + (outcome == 6 ? 1 : 0));
    bad_length = outcome == 4 ? (socklen_t *)1 : outcome == 7 ? NULL : length;
    output_fault = 0;
    int jumped = sigsetjmp(output_escape, 1);
    if (!jumped) {
      int accepted = accept4(listener, bad_address, bad_length,
                             SOCK_NONBLOCK | SOCK_CLOEXEC);
      if (outcome == 1 || outcome == 2 || outcome == 3 || outcome == 7) {
        CHECK(accepted == -1 && errno == EFAULT);
        CHECK(native(680, 0, 0, 0) == baseline);
        *(volatile char *)(page + (outcome == 1 ? 0 : 4096)) = 1;
        CHECK(0);
      }
      CHECK(accepted == expected);
      CHECK((fcntl(accepted, F_GETFL) & O_NONBLOCK) &&
            (fcntl(accepted, F_GETFD) & FD_CLOEXEC));
      if (outcome == 5 || outcome == 6)
        CHECK(*length == 2 && page[0] == 0xa5 && page[2] == 0xa5);
      CHECK(close(accepted) == 0);
    } else
      CHECK(outcome != 0 && jumped == 37 && output_fault);
    CHECK(output_fault == (outcome == 1 || outcome == 2 || outcome == 3 || outcome == 7));
    if (outcome == 3 || outcome == 7) {
      /* A rejected input length must not consume the queued connection. */
      int retained = accept(listener, NULL, NULL);
      CHECK(retained == expected && close(retained) == 0);
    }
    CHECK(native(680, 0, 0, 0) == baseline);
    int duplicate = dup(listener);
    CHECK(duplicate == expected && close(duplicate) == 0);
    CHECK(munmap(page, 8192) == 0 && close(listener) == 0 &&
          close(client) == 0);
    CHECK(unlink(destination.sun_path) == 0 && native(680, 0, 0, 0) == start);
    fprintf(stderr, "connection-resources: output=%u PASS\n", outcome);
  }
  puts("connection-resources: PASS 8 blocked connect/accept and 8 accept "
       "publication/EFAULT cases including active handlers and optional/truncated addresses");
  return 0;
}
