/* Real mochiOS integration. Run with no option for all modes, or --pipe,
 * --socket (recv),
 * --socket-read, --readv, --socket-readv, --poll, --select, --socket-poll,
 * and --socket-select. Link with the fresh runtime;
 * host execution cannot validate native COW, Handle inheritance or exec. */
#define _GNU_SOURCE 1
#include <elf.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <reent.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "fork-live: FAIL line=%d errno=%d\n", __LINE__, errno);  \
      return 1;                                                                \
    }                                                                          \
  } while (0)
extern char **environ;
static atomic_int ready, cleaned, tls_cleaned, worker_error;
static atomic_uint_fast64_t worker_handle;
static int blocked_pipe[2];
static int socket_wait;
static int vector_wait;
static int multiplex_wait;
static int64_t native(uint64_t number, uint64_t a, uint64_t b) {
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(a), "S"(b)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
static pthread_key_t key;
static struct _reent *foreign_reent;
static void cleanup(struct _reent *unused) {
  (void)unused;
  atomic_fetch_add(&cleaned, 1);
}
static void tls_cleanup(void *value) {
  if (value != (void *)(uintptr_t)17)
    atomic_store(&worker_error, 1);
  atomic_fetch_add(&tls_cleaned, 1);
}
static void *worker(void *unused) {
  (void)unused;
  struct _reent *reent = __getreent();
  if (_REENT_CVTBUF(reent) || pthread_setspecific(key, (void *)(uintptr_t)17)) {
    atomic_store(&worker_error, 1);
    atomic_store_explicit(&ready, 1, memory_order_release);
    return NULL;
  }
  // Deliberately model an interrupted cache update. Neither fork-child
  // cleanup nor a TLS destructor may try to follow this private pointer.
  _REENT_CVTBUF(reent) = (char *)(uintptr_t)1;
  _REENT_CLEANUP(reent) = cleanup;
  foreign_reent = reent;
  int64_t handle = native(656, 0, 0);
  if (handle <= 0) {
    _REENT_CVTBUF(reent) = NULL;
    atomic_store(&worker_error, 1);
    atomic_store(&ready, 1);
    return NULL;
  }
  atomic_store(&worker_handle, (uint64_t)handle);
  atomic_store_explicit(&ready, 1, memory_order_release);
  char release[2] = {0};
  struct iovec vectors[2] = {{release, 1}, {release + 1, 1}};
  if (multiplex_wait) {
    struct pollfd descriptor = {blocked_pipe[0], POLLIN, 0};
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(blocked_pipe[0], &readfds);
    int status = multiplex_wait == 1
                     ? poll(&descriptor, 1, -1)
                     : select(blocked_pipe[0] + 1, &readfds, NULL, NULL, NULL);
    if (status != 1)
      atomic_store(&worker_error, 1);
  }
  ssize_t count = vector_wait        ? readv(blocked_pipe[0], vectors, 2)
                  : socket_wait == 1 ? recv(blocked_pipe[0], release, 1, 0)
                                     : read(blocked_pipe[0], release, 1);
  if (count != (vector_wait ? 2 : 1) || release[0] != 'R' ||
      (vector_wait && release[1] != '!'))
    atomic_store(&worker_error, 1);
  _REENT_CVTBUF(reent) = NULL; // parent exit/join may now reclaim normally
  return NULL;
}
static int run_mode(int argc, char **argv, char **envp) {
  CHECK(argc >= 1 && argv[0] && *argv[0]);
  fprintf(stderr, "fork-live: BEGIN mode=%s\n", argv[1]);
  // argv[0] is an application label, not necessarily an executable pathname.
  // Resolve our image from the native initial stack before creating a thread.
  while (*envp)
    ++envp;
  const uintptr_t *auxiliary = (const uintptr_t *)(envp + 1);
  const char *executable = NULL;
  for (; auxiliary[0] != AT_NULL; auxiliary += 2)
    if (auxiliary[0] == AT_EXECFN)
      executable = (const char *)auxiliary[1];
  CHECK(executable && executable[0] == '/');
  atomic_store(&ready, 0);
  atomic_store(&cleaned, 0);
  atomic_store(&tls_cleaned, 0);
  atomic_store(&worker_error, 0);
  atomic_store(&worker_handle, 0);
  foreign_reent = NULL;
  socket_wait = argc == 2 && strcmp(argv[1], "--socket") == 0;
  if (argc == 2 && strcmp(argv[1], "--socket-read") == 0)
    socket_wait = 2;
  vector_wait = argc == 2 && (strcmp(argv[1], "--readv") == 0 ||
                              strcmp(argv[1], "--socket-readv") == 0);
  if (vector_wait && strcmp(argv[1], "--socket-readv") == 0)
    socket_wait = 2;
  if (argc == 2) {
    if (strcmp(argv[1], "--poll") == 0 || strcmp(argv[1], "--socket-poll") == 0)
      multiplex_wait = 1;
    if (strcmp(argv[1], "--select") == 0 ||
        strcmp(argv[1], "--socket-select") == 0)
      multiplex_wait = 2;
    if (multiplex_wait && strncmp(argv[1], "--socket-", 9) == 0)
      socket_wait = 2;
  }
  CHECK(pthread_key_create(&key, tls_cleanup) == 0);
  CHECK((socket_wait ? socketpair(AF_UNIX, SOCK_STREAM, 0, blocked_pipe)
                     : pipe(blocked_pipe)) == 0);
  pthread_t thread;
  CHECK(pthread_create(&thread, NULL, worker, NULL) == 0);
  while (!atomic_load_explicit(&ready, memory_order_acquire))
    sched_yield();
  CHECK(!atomic_load(&worker_error) && foreign_reent);
  // Observe a real native blocked state, not just a flag before read(). The
  // writer stays open and empty, so the foreign FD-only scope remains live.
  struct {
    uint64_t thread, process;
    uint32_t state, reserved;
  } thread_status;
  uint64_t handle = atomic_load(&worker_handle);
  struct timespec started, now;
  CHECK(clock_gettime(CLOCK_MONOTONIC, &started) == 0);
  do {
    CHECK(native(658, handle, (uint64_t)&thread_status) == 0);
    CHECK(!atomic_load(&worker_error) && thread_status.state != 5);
    if (thread_status.state != 3 && thread_status.state != 4)
      sched_yield();
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    if (now.tv_sec - started.tv_sec >= 10) {
      fprintf(stderr, "fork-live: worker did not block mode=%s state=%u\n",
              argv[1], thread_status.state);
      return 1;
    }
  } while (thread_status.state != 3 && thread_status.state != 4);
  CHECK(native(626, handle, 0) == 0);
  fprintf(stderr, "fork-live: sibling blocked mode=%s\n", argv[1]);
  for (unsigned round = 0; round < 3; ++round) {
    int channel[2];
    CHECK(pipe(channel) == 0);
    pid_t child = -1;
    for (unsigned attempt = 0; attempt < 100; ++attempt) {
      child = fork();
      if (child >= 0 || errno != EAGAIN)
        break;
      sched_yield();
    }
    CHECK(child >= 0);
    if (child == 0) {
      // No allocation, stdio, foreign TLS destruction or cache walk
      // occurs between the multithreaded fork and execve.
      if (atomic_load(&cleaned) || atomic_load(&tls_cleaned))
        _exit(51);
      if (_REENT_CVTBUF(foreign_reent) != (char *)(uintptr_t)1)
        _exit(52);
      char marker = 'C';
      if (close(channel[0]) || write(channel[1], &marker, 1) != 1 ||
          close(channel[1]))
        _exit(53);
      char *arguments[] = {argv[0], "--fork-child", NULL};
      execve(executable, arguments, environ);
      // Preserve the full exec error without allocation, stdio, or truncating
      // errno to the eight-bit child exit status. write is async-signal-safe.
      unsigned error = (unsigned)errno;
      char message[] = "fork-live: child exec errno=0000000000\n";
      for (size_t digit = 0; digit < 10; ++digit) {
        message[sizeof(message) - 3 - digit] = '0' + error % 10;
        error /= 10;
      }
      (void)write(STDERR_FILENO, message, sizeof(message) - 1);
      _exit(54);
    }
    fprintf(stderr, "fork-live: parent round=%u child=%d mode=%s\n", round,
            child, argv[1]);
    CHECK(close(channel[1]) == 0);
    char marker = 0;
    CHECK(read(channel[0], &marker, 1) == 1 && marker == 'C');
    CHECK(close(channel[0]) == 0);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status));
    if (WEXITSTATUS(status))
      fprintf(stderr, "fork-live: child status=%d\n", WEXITSTATUS(status));
    CHECK(WEXITSTATUS(status) == 0);
    CHECK(!atomic_load(&cleaned) && !atomic_load(&tls_cleaned));
  }
  CHECK(write(blocked_pipe[1], "R!", vector_wait ? 2 : 1) ==
        (vector_wait ? 2 : 1));
  CHECK(pthread_join(thread, NULL) == 0);
  CHECK(!atomic_load(&worker_error));
  CHECK(atomic_load(&cleaned) == 1 && atomic_load(&tls_cleaned) == 1);
  CHECK(pthread_key_delete(key) == 0);
  CHECK(close(blocked_pipe[0]) == 0 && close(blocked_pipe[1]) == 0);
  fprintf(stderr,
          "fork-live: PASS mode=%s, three forks, inherited pipe, "
          "child exec and parent-only destructors\n",
          argv[1]);
  return 0;
}

int main(int argc, char **argv, char **envp) {
  if (argc == 2 && strcmp(argv[1], "--fork-child") == 0)
    return 0;
  static const char *const modes[] = {
      "--pipe", "--socket", "--socket-read", "--readv",        "--socket-readv",
      "--poll", "--select", "--socket-poll", "--socket-select"};
  for (size_t mode = 0; mode < sizeof(modes) / sizeof(modes[0]); ++mode) {
    if (argc == 2 && strcmp(argv[1], modes[mode]) == 0)
      return run_mode(argc, argv, envp);
  }
  // Service launchers may supply their own logger argument. Such an invocation
  // runs the whole matrix; only explicit mode names select a single case.
  for (size_t mode = 0; mode < sizeof(modes) / sizeof(modes[0]); ++mode) {
    char *arguments[] = {argv[0], (char *)modes[mode], NULL};
    int result = run_mode(2, arguments, envp);
    if (result)
      return result;
  }
  fputs("fork-live: PASS all nine I/O wait modes\n", stderr);
  return 0;
}
