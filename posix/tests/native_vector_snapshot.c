/* The caller's iovec array ceases to exist while actual native I/O sleeps.
 * Only the captured addresses/lengths may be used after the handler returns. */
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
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#ifdef WITH_IO_ESCAPE_REGRESSION
int native_io_resource_escape_main(void);
#endif

static struct iovec *supplied;
static size_t mapping_length;
static unsigned count, writing, unmap_input;
static int pipes[2];
static char decoy[16];
static atomic_uint thread_handle;
static volatile sig_atomic_t handler_error, handled;
static unsigned fault_input;
static volatile sig_atomic_t capture_fault;
static sigjmp_buf capture_escape;
struct thread_status {
  uint64_t thread, process;
  uint32_t state, reserved;
};
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr,                                                          \
              "vector-snapshot: FAIL count=%u writing=%u unmap=%u line=%u "    \
              "errno=%d handler=%d: %s\n",                                     \
              count, writing, unmap_input, __LINE__, errno,                    \
              (int)handler_error, #x);                                         \
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
static void handler(int signal) {
  if (signal == SIGSEGV) {
    if (fault_input) {
      capture_fault = 1;
      siglongjmp(capture_escape, 37);
    }
    static const char failure[] = "vector-snapshot: unexpected SIGSEGV\n";
    native(660, (uintptr_t)failure, sizeof(failure) - 1, 0);
    _exit(90);
  }
  if (signal != SIGUSR1)
    return;
  if (unmap_input) {
    if (munmap(supplied, mapping_length))
      handler_error = 1;
  } else {
    supplied[0] = (struct iovec){decoy, 7};
    supplied[1] = (struct iovec){NULL, 0};
  }
  if (writing) {
    char bytes[512];
    ssize_t result;
    do {
      result = read(pipes[0], bytes, sizeof(bytes));
    } while (result > 0);
    if (result != -1 || errno != EAGAIN)
      handler_error = 2;
  } else if (write(pipes[1], "abcDEFG", 7) != 7)
    handler_error = 3;
  handled = 1;
}
static void *worker(void *unused) {
  (void)unused;
  char first[3] = {'a', 'b', 'c'}, second[4] = {'D', 'E', 'F', 'G'};
  if (!writing) {
    memset(first, 0, sizeof(first));
    memset(second, 0, sizeof(second));
  }
  supplied[0] = (struct iovec){first, sizeof(first)};
  supplied[1] = (struct iovec){second, sizeof(second)};
  int64_t handle =
      native(656, 0, 0, 0); /* own ThreadHandle, not a PID/FD lookup */
  if (handle <= 0)
    return (void *)1;
  atomic_store_explicit(&thread_handle, (unsigned)handle, memory_order_release);
  if (fault_input) {
    int jumped = sigsetjmp(capture_escape, 1);
    if (jumped)
      return jumped == 37 && capture_fault ? NULL : (void *)3;
    if (mprotect(supplied, mapping_length, PROT_NONE))
      return (void *)4;
  }
  ssize_t result = writing ? writev(pipes[1], supplied, (int)count)
                           : readv(pipes[0], supplied, (int)count);
  if (result != 7 || memcmp(first, "abc", 3) || memcmp(second, "DEFG", 4))
    return (void *)2;
  return NULL;
}
static void *warm(void *unused) { return unused; }
int main(void) {
  _Static_assert(sizeof(struct thread_status) == 24, "native thread status");
  _Static_assert(sizeof(struct iovec) == 16, "native userspace vector ABI");
  struct sigaction action = {0};
  action.sa_handler = handler;
  action.sa_flags = SA_RESTART;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
  struct sigaction previous_fault;
  CHECK(sigaction(SIGSEGV, &action, &previous_fault) == 0);
  pthread_t thread;
  void *result;
  CHECK(pthread_create(&thread, NULL, warm, NULL) == 0);
  CHECK(pthread_join(thread, &result) == 0 && result == NULL);
  fprintf(stderr, "vector-snapshot: start inline/spilled/IOV_MAX metadata\n");
  const unsigned counts[3] = {2, 9, 1024};
  for (unsigned size = 0; size < 3; ++size) {
    count = counts[size];
    for (writing = 0; writing < 2; ++writing) {
      for (unmap_input = 0; unmap_input < 2; ++unmap_input) {
        int64_t baseline = native(680, 0, 0, 0);
        CHECK(baseline > 0 && pipe(pipes) == 0);
        mapping_length = (count * sizeof(*supplied) + 4095) & ~(size_t)4095;
        supplied = mmap(NULL, mapping_length, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(supplied != MAP_FAILED);
        memset(supplied, 0, mapping_length);
        memset(decoy, 0, sizeof(decoy));
        if (writing) {
          CHECK(fcntl(pipes[1], F_SETFL, O_NONBLOCK) == 0);
          char fill[512];
          memset(fill, 'f', sizeof(fill));
          while (write(pipes[1], fill, sizeof(fill)) == sizeof(fill)) {
          }
          CHECK(errno == EAGAIN && fcntl(pipes[1], F_SETFL, 0) == 0);
          CHECK(fcntl(pipes[0], F_SETFL, O_NONBLOCK) == 0);
        }
        atomic_store(&thread_handle, 0);
        handled = handler_error = 0;
        CHECK(pthread_create(&thread, NULL, worker, NULL) == 0);
        unsigned handle = 0, attempt;
        struct thread_status status = {0};
        for (attempt = 0; attempt < 5000; ++attempt) {
          handle = atomic_load_explicit(&thread_handle, memory_order_acquire);
          if (handle) {
            CHECK(native(658, handle, (uintptr_t)&status, 0) == 0);
            if (status.state == 3 || status.state == 4)
              break;
            CHECK(status.state != 5);
          }
          struct timespec delay = {0, 1000000};
          CHECK(nanosleep(&delay, NULL) == 0);
        }
        CHECK(attempt < 5000 && handle != 0);
        CHECK(pthread_kill(thread, SIGUSR1) == 0);
        CHECK(pthread_join(thread, &result) == 0 && result == NULL);
        CHECK(handled && !handler_error &&
              memcmp(decoy, (char[16]){0}, 16) == 0);
        if (writing) {
          char bytes[8] = {0};
          CHECK(read(pipes[0], bytes, 7) == 7 &&
                memcmp(bytes, "abcDEFG", 7) == 0);
        }
        CHECK(native(626, handle, 0, 0) == 0);
        CHECK(close(pipes[0]) == 0 && close(pipes[1]) == 0);
        if (!unmap_input)
          CHECK(munmap(supplied, mapping_length) == 0);
        CHECK(native(680, 0, 0, 0) == baseline);
        fprintf(stderr, "vector-snapshot: count=%u writing=%u unmap=%u PASS\n",
                count, writing, unmap_input);
      }
    }
  }
  puts("vector-snapshot: PASS 12 observed blocked I/O cases; captured metadata "
       "survives overwrite/unmap, correct payload and Handle counts");
  fault_input = 1;
  writing = 0;
  unmap_input = 0;
  for (unsigned size = 0; size < 3; ++size) {
    count = counts[size];
    int64_t baseline = native(680, 0, 0, 0);
    CHECK(baseline > 0 && pipe(pipes) == 0);
    mapping_length = (count * sizeof(*supplied) + 4095) & ~(size_t)4095;
    supplied = mmap(NULL, mapping_length, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(supplied != MAP_FAILED);
    memset(supplied, 0, mapping_length);
    atomic_store(&thread_handle, 0);
    capture_fault = 0;
    CHECK(pthread_create(&thread, NULL, worker, NULL) == 0);
    CHECK(pthread_join(thread, &result) == 0 && result == NULL &&
          capture_fault);
    unsigned handle = atomic_load(&thread_handle);
    CHECK(handle != 0 && native(626, handle, 0, 0) == 0);
    CHECK(close(pipes[0]) == 0 && close(pipes[1]) == 0);
    CHECK(munmap(supplied, mapping_length) == 0);
    CHECK(native(680, 0, 0, 0) == baseline);
    fprintf(stderr,
            "vector-snapshot: count=%u synchronous capture fault PASS\n",
            count);
  }
  puts("vector-snapshot: PASS 3 synchronous initialization faults; nonlocal "
       "exit reclaims partially initialized resources");
  CHECK(sigaction(SIGSEGV, &previous_fault, NULL) == 0);
  fault_input = 0;
#ifdef WITH_IO_ESCAPE_REGRESSION
  return native_io_resource_escape_main();
#else
  return 0;
#endif
}
