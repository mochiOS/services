/* Real upcalls interrupt a blocked I/O operation. Closing/reusing its FD in
 * the handler must not invalidate its captured reference or leak that reference
 * when C abandons the Rust frame. No runtime test hooks are used. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

struct handle_info {
  uint32_t handle, reserved;
  uint64_t rights;
};
static struct handle_info before[128], after[128];
static unsigned kind, outcome;
static int pipes[2], source, peer;
static uint32_t source_handle, second_socket_handle;
static atomic_int entered;
static atomic_uint worker_handle;
struct thread_status {
  uint64_t thread, process;
  uint32_t state, reserved;
};
static volatile sig_atomic_t armed, qualified, handler_error;
static sigjmp_buf destination;
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr,                                                          \
              "io-escape: FAIL kind=%u outcome=%u line=%u errno=%d "           \
              "handler=%d: %s\n",                                              \
              kind, outcome, __LINE__, errno, (int)handler_error, #x);         \
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
static int snapshot(struct handle_info *records) {
  return (int)native(680, (uintptr_t)records, 128, 0);
}
static int present(uint32_t id, int count) {
  for (int index = 0; index < count; ++index)
    if (before[index].handle == id)
      return 1;
  return 0;
}
static void handler(int signal) {
  if (!armed || signal != (kind == 8 ? SIGXFSZ : SIGUSR1))
    return;
  armed = 0;
  if (close(source) != 0)
    handler_error = 1;
  /* This is the coverage gate: a pre-I/O signal would close the native Handle
   * immediately, rather than leave the operation's already acquired pin. */
  if ((uint64_t)native(664, source_handle, 0, 0) >= (uint64_t)-4095 ||
      (second_socket_handle &&
       (uint64_t)native(664, second_socket_handle, 0, 0) >= (uint64_t)-4095))
    handler_error = 2;
  else
    qualified = 1;
  if (dup(peer) != source)
    handler_error = 3;
  if (outcome == 1)
    siglongjmp(destination, 37);
  if (outcome == 2)
    pthread_exit((void *)0x55);
  if (kind == 8)
    return;
  char bytes[512];
  if (kind & 1) {
    if (read(peer, bytes, sizeof(bytes)) != sizeof(bytes))
      handler_error = 4;
  } else if (write(peer, "abcDEFG", 7) != 7)
    handler_error = 5;
}
static void *worker(void *unused) {
  (void)unused;
  int jumped = sigsetjmp(destination, 1);
  if (jumped)
    return jumped == 37 ? (void *)0x37 : (void *)1;
  char first[3] = {0}, second[4] = {0};
  char bytes[8] = "abcDEFG";
  struct iovec vectors[9] = {
      {kind & 1 ? (void *)bytes : (void *)first, 3},
      {kind & 1 ? (void *)(bytes + 3) : (void *)second, 4}};
  if (kind < 8) {
    int64_t handle = native(656, 0, 0, 0);
    if (handle <= 0)
      return (void *)6;
    atomic_store_explicit(&worker_handle, (unsigned)handle,
                          memory_order_release);
  }
  atomic_store_explicit(&entered, 1, memory_order_release);
  ssize_t result;
  switch (kind) {
  case 0:
    result = read(source, bytes, 7);
    break;
  case 1:
    result = write(source, bytes, 7);
    break;
  case 2:
    result = readv(source, vectors, 9);
    break;
  case 3:
    result = writev(source, vectors, 9);
    break;
  case 4:
    result = recv(source, bytes, 7, 0);
    break;
  case 5:
    result = send(source, bytes, 7, 0);
    break;
  case 6:
    result = outcome < 2 ? recvfrom(source, bytes, 7, 0, NULL, NULL)
                         : recv(source, bytes, 7, 0);
    break;
  case 7:
    result = send(source, bytes, 7, 0);
    break;
  default:
    result = pwrite(source, bytes, 7, 0);
    return result == -1 && errno == EFBIG ? NULL : (void *)5;
  }
  if (result != 7)
    return (void *)2;
  if ((kind == 0 || kind == 4 || kind == 6) && memcmp(bytes, "abcDEFG", 7))
    return (void *)3;
  if (kind == 2 && (memcmp(first, "abc", 3) || memcmp(second, "DEFG", 4)))
    return (void *)4;
  return NULL;
}
static void *warm_thread(void *unused) { return unused; }
int main(void) {
  _Static_assert(sizeof(sigjmp_buf) == 120, "mochiOS nonlocal signal ABI");
  struct sigaction action = {0};
  action.sa_handler = handler;
  action.sa_flags = SA_RESTART;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
  CHECK(sigaction(SIGXFSZ, &action, NULL) == 0);
  CHECK(raise(SIGUSR1) == 0);
  pthread_t thread;
  void *result;
  CHECK(pthread_create(&thread, NULL, warm_thread, NULL) == 0);
  CHECK(pthread_join(thread, &result) == 0 && result == NULL);
  CHECK(pipe(pipes) == 0 && close(pipes[0]) == 0 && close(pipes[1]) == 0);
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pipes) == 0 &&
        close(pipes[0]) == 0 && close(pipes[1]) == 0);
  /* Initialize the process-owned worker endpoint before leak baselines. */
  char warm = 0;
  CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, pipes) == 0);
  CHECK(send(pipes[0], "w", 1, 0) == 1 && recv(pipes[1], &warm, 1, 0) == 1 &&
        warm == 'w');
  CHECK(close(pipes[0]) == 0 && close(pipes[1]) == 0);
  fprintf(stderr, "io-escape: start blocked scalar/vector/socket I/O\n");
  for (kind = 0; kind < 8; ++kind) {
    for (outcome = 0; outcome < 4; ++outcome) {
      int baseline = snapshot(before);
      CHECK(baseline > 0 && baseline < 126);
      CHECK(kind < 4 ? pipe(pipes) == 0
                     : socketpair(AF_UNIX, kind < 6 ? SOCK_STREAM : SOCK_DGRAM,
                                  0, pipes) == 0);
      int count = snapshot(after);
      CHECK(count == baseline + 2);
      source = pipes[kind & 1];
      peer = pipes[!(kind & 1)];
      source_handle = 0;
      second_socket_handle = 0;
      for (int index = 0; index < count; ++index)
        if (!present(after[index].handle, baseline)) {
          if (kind >= 4) {
            if (source_handle == 0)
              source_handle = after[index].handle;
            else
              second_socket_handle = after[index].handle;
          } else if ((after[index].rights & 3) == (kind & 1 ? 2 : 1))
            source_handle = after[index].handle;
        }
      CHECK(source_handle != 0 && (kind < 4 || second_socket_handle != 0));
      if (kind & 1) {
        CHECK(fcntl(source, F_SETFL, O_NONBLOCK) == 0);
        char fill[512];
        memset(fill, 'f', sizeof(fill));
        while (write(source, fill, sizeof(fill)) == sizeof(fill)) {
        }
        CHECK(errno == EAGAIN && fcntl(source, F_SETFL, 0) == 0);
      }
      qualified = handler_error = 0;
      armed = outcome != 3;
      atomic_store(&entered, 0);
      atomic_store(&worker_handle, 0);
      CHECK(pthread_create(&thread, NULL, worker, NULL) == 0);
      while (!atomic_load_explicit(&entered, memory_order_acquire))
        CHECK(sched_yield() == 0);
      /* Observe an actual blocked native thread, rather than assuming that
       * a delay means the FD lease has been acquired. */
      unsigned handle =
          atomic_load_explicit(&worker_handle, memory_order_acquire);
      CHECK(handle != 0);
      struct thread_status status = {0};
      unsigned attempt;
      for (attempt = 0; attempt < 5000; ++attempt) {
        CHECK(native(658, handle, (uintptr_t)&status, 0) == 0);
        if (status.state == 3 || status.state == 4) {
          /* Two sockets, the runtime's own thread Handle, this observer's
           * thread Handle, staged RAM, and (send only) the wait-job Handle.
           * A worker RPC alone does not prove these resources exist yet. */
          if (kind < 6 || native(680, 0, 0, 0) == baseline + 5 + (kind & 1))
            break;
        }
        CHECK(status.state != 5);
        struct timespec delay = {0, 1000000};
        CHECK(nanosleep(&delay, NULL) == 0);
      }
      if (attempt == 5000)
        fprintf(stderr,
                "io-escape: readiness baseline=%d current=%lld state=%u\n",
                baseline, (long long)native(680, 0, 0, 0), status.state);
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
      CHECK(close(source) == 0 && close(peer) == 0);
      CHECK(snapshot(after) == baseline);
      fprintf(stderr, "io-escape: kind=%u outcome=%u PASS\n", kind, outcome);
    }
  }
  struct rlimit original, limited;
  CHECK(getrlimit(RLIMIT_FSIZE, &original) == 0);
  limited = original;
  limited.rlim_cur = 0;
  char path[96];
  snprintf(path, sizeof(path), "/tmp/io-resource-escape-%d", (int)getpid());
  kind = 8;
  second_socket_handle = 0;
  for (outcome = 0; outcome < 3; ++outcome) {
    int baseline = snapshot(before);
    CHECK(baseline > 0 && baseline < 126);
    source = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    CHECK(source >= 0);
    int count = snapshot(after);
    CHECK(count == baseline + 1);
    source_handle = 0;
    for (int index = 0; index < count; ++index)
      if (!present(after[index].handle, baseline))
        source_handle = after[index].handle;
    CHECK(source_handle != 0);
    peer = dup(source);
    CHECK(peer >= 0 && setrlimit(RLIMIT_FSIZE, &limited) == 0);
    qualified = handler_error = 0;
    armed = 1;
    CHECK(pthread_create(&thread, NULL, worker, NULL) == 0);
    CHECK(pthread_join(thread, &result) == 0);
    CHECK(setrlimit(RLIMIT_FSIZE, &original) == 0);
    CHECK(result == (outcome == 0   ? NULL
                     : outcome == 1 ? (void *)0x37
                                    : (void *)0x55));
    CHECK(!handler_error && qualified);
    CHECK(close(source) == 0 && close(peer) == 0 && unlink(path) == 0);
    CHECK(snapshot(after) == baseline);
    fprintf(stderr, "io-escape: pwrite outcome=%u PASS\n", outcome);
  }
  puts(
      "io-escape: PASS 35 qualified scalar/vector/socket/positioned I/O cases; "
      "returning handlers, siglongjmp, pthread_exit, cancellation, descriptor "
      "reuse and native Handle reclamation");
  return 0;
}
