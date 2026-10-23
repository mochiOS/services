/* The baseline also covers foreign-thread fork and cancellation ordering. */
#define main cpu_sleep_baseline
#include "native_cpu_sleep.c"
#undef main

static volatile sig_atomic_t handler_child, handler_error, handler_depth;
static volatile sig_atomic_t descendant, child_pipe_count, child_rights;
static volatile sig_atomic_t reused_handle;
static volatile sig_atomic_t child_pipes[1][2];

static void fork_cpu_wait(int signal) {
  if (signal != SIGUSR2) { handler_error = 1; return; }
  for (sig_atomic_t depth = 0; depth < handler_depth; ++depth) {
    pid_t child = fork();
    if (child < 0) { handler_error = 2; return; }
    descendant = child;
    if (child) break;
    handler_child = 1;
  }
  if (!handler_child) return;
  /* A copied old lease must not close a new occupant of its old native slot.
   * Startup can already have reused it for a thread reference. Otherwise
   * cycle native references without exhausting the global stream table. */
  int pair[2];
  if (pipe(pair)) { handler_error = 3; return; }
  child_pipes[0][0] = pair[0];
  child_pipes[0][1] = pair[1];
  child_pipe_count = 1;
  uint64_t label = atomic_load(&private_label);
  int64_t rights = native(664, label, 0);
  if (rights < 0) {
    int64_t object = native(671, 4096, 0);
    if (object <= 0) { handler_error = 5; return; }
    if ((uint64_t)object == label) {
      reused_handle = (sig_atomic_t)object;
    } else {
      for (unsigned attempt = 0; attempt < 4096; ++attempt) {
        int64_t duplicate = native(627, (uint64_t)object, 1);
        if (duplicate <= 0) { handler_error = 6; break; }
        if ((uint64_t)duplicate == label) {
          reused_handle = (sig_atomic_t)duplicate;
          break;
        }
        if (native(626, (uint64_t)duplicate, 0)) { handler_error = 7; break; }
      }
      if (native(626, (uint64_t)object, 0)) handler_error = 8;
    }
    rights = native(664, label, 0);
  }
  if (rights < 0 || rights == 17) handler_error = 4;
  child_rights = (sig_atomic_t)rights;
}

static void *notify_fork_wait(void *unused) {
  (void)unused;
  uint64_t label, started = cpu();
  while (!(label = find_private())) {
    if (cpu() - started > 5000000000) return (void *)1;
    sched_yield();
  }
  if (label == UINT64_MAX) return (void *)2;
  atomic_store(&private_label, label);
  return (void *)(uintptr_t)(pthread_kill(main_thread, SIGUSR2) != 0);
}

int main(void) {
  CHECK(cpu_sleep_baseline() == 0);
  struct sigaction action = {.sa_handler = fork_cpu_wait, .sa_flags = SA_RESTART};
  CHECK(sigemptyset(&action.sa_mask) == 0);
  CHECK(sigaction(SIGUSR2, &action, NULL) == 0);
  for (unsigned mode = 0; mode < 4; ++mode) {
    unsigned absolute = mode / 2, nested = mode % 2;
    handler_child = handler_error = descendant = child_pipe_count = child_rights = reused_handle = 0;
    handler_depth = nested + 1;
    pthread_t notifier;
    CHECK(pthread_create(&notifier, NULL, notify_fork_wait, NULL) == 0);
    struct timespec deadline = timespec(absolute ? cpu() + 100000000000 : 100000000000);
    struct timespec remaining = {99, 99};
    errno = EDOM;
    int result = clock_nanosleep(CLOCK_PROCESS_CPUTIME_ID, absolute ? TIMER_ABSTIME : 0,
                                &deadline, &remaining);
    if (handler_child) {
      if (handler_error) _exit(80 + handler_error);
      if (result != EINTR) _exit(100 + result);
      if (errno != EDOM) _exit(76);
      if (absolute ? remaining.tv_sec != 99 || remaining.tv_nsec != 99
                   : remaining.tv_sec <= 0 || remaining.tv_sec > 100
                     || remaining.tv_nsec < 0 || remaining.tv_nsec >= 1000000000) _exit(75);
      if (native(664, atomic_load(&private_label), 0) != child_rights) _exit(72);
      if (reused_handle && native(626, (uint64_t)reused_handle, 0)) _exit(77);
      for (sig_atomic_t n = 0; n < child_pipe_count; ++n) {
        char marker;
        if (write(child_pipes[n][1], "C", 1) != 1
            || read(child_pipes[n][0], &marker, 1) != 1 || marker != 'C'
            || close(child_pipes[n][0]) || close(child_pipes[n][1])) _exit(73);
      }
      if (descendant > 0) {
        int status;
        if (waitpid(descendant, &status, 0) != descendant
            || !WIFEXITED(status) || WEXITSTATUS(status)) _exit(74);
      }
      _exit(0);
    }
    CHECK(!handler_error && descendant > 0);
    CHECK(result == EINTR && errno == EDOM);
    CHECK(absolute ? remaining.tv_sec == 99 && remaining.tv_nsec == 99
                   : remaining.tv_sec > 0 && remaining.tv_sec <= 100
                     && remaining.tv_nsec >= 0 && remaining.tv_nsec < 1000000000);
    void *notification = (void *)1;
    CHECK(pthread_join(notifier, &notification) == 0 && notification == NULL);
    int status;
    pid_t waited = waitpid(descendant, &status, 0);
    if (waited != descendant || status)
      fprintf(stderr, "cpu-sleep-fork: child outcome waited=%d status=%d\n", waited, status);
    CHECK(waited == descendant && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    fprintf(stderr, "cpu-sleep-fork: PASS absolute=%u returning handler depth=%u, child slot reuse and parent reference lifetime\n", absolute, nested + 1);
  }
  return 0;
}
