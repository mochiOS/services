#define main nonblocking_record_lock_main
#include "native_record_lock.c"
#undef main
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <time.h>

struct worker_state {
  int fd, mode, result, error, setup;
  atomic_int ready, release, done, cleaned, acquired;
};
static atomic_int handled;
static void handler(int signal) {
  (void)signal;
  atomic_fetch_add(&handled, 1);
}
static void cleanup(void *pointer) {
  struct worker_state *state = pointer;
  atomic_fetch_add(&state->cleaned, 1);
}
static void pause_ms(long milliseconds) {
  struct timespec value = {milliseconds / 1000,
                           (milliseconds % 1000) * 1000000};
  while (nanosleep(&value, &value) < 0 && errno == EINTR) {
  }
}
static int await(atomic_int *value) {
  for (int i = 0; i < 5000; i++) {
    if (atomic_load_explicit(value, memory_order_acquire))
      return 0;
    pause_ms(1);
  }
  return -1;
}
static void *wait_worker(void *pointer) {
  struct worker_state *state = pointer;
  pthread_cleanup_push(cleanup, state);
  if (state->mode == 4)
    state->setup = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
  if (state->mode == 5)
    state->setup = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
  atomic_store_explicit(&state->ready, 1, memory_order_release);
  if (state->mode == 6) {
    while (!atomic_load_explicit(&state->release, memory_order_acquire))
      sched_yield();
  }
  struct flock value = {
      .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 10, .l_len = 20};
  errno = 0;
  state->result = fcntl(state->fd, F_SETLKW, &value);
  state->error = errno;
  atomic_store_explicit(&state->done, 1, memory_order_release);
  if (state->result == 0)
    atomic_store(&state->acquired, 1);
  if (state->mode == 4) {
    if (set(state->fd, F_UNLCK) != 0)
      state->setup = errno;
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) != 0)
      state->setup = 999;
    pthread_testcancel();
  }
  pthread_cleanup_pop(0);
  return NULL;
}

static int run_wait_case(int mode) {
  fprintf(stderr, "wait-lock: case %d\n", mode);
  const char *path = "/tmp/native-libc-lock-wait-161";
  unlink(path);
  int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
  CHECK(fd >= 0);
  int ready[2], go[2];
  CHECK(pipe(ready) == 0 && pipe(go) == 0);
  pid_t holder = fork();
  CHECK(holder >= 0);
  if (!holder) {
    CHECK(close(ready[0]) == 0 && close(go[1]) == 0);
    CHECK(set(fd, F_WRLCK) == 0 && write(ready[1], "R", 1) == 1);
    char byte;
    CHECK(read(go[0], &byte, 1) == 1);
    CHECK(set(fd, F_UNLCK) == 0);
    _exit(0);
  }
  CHECK(close(ready[1]) == 0 && close(go[0]) == 0);
  char byte;
  CHECK(read(ready[0], &byte, 1) == 1 && byte == 'R');
  struct sigaction action = {0};
  action.sa_handler = handler;
  action.sa_flags = mode == 3 ? SA_RESTART : 0;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
  atomic_store(&handled, 0);
  struct worker_state state = {.fd = fd, .mode = mode, .result = -999};
  pthread_t worker;
  CHECK(pthread_create(&worker, NULL, wait_worker, &state) == 0);
  CHECK(await(&state.ready) == 0 && state.setup == 0);
  if (mode != 6)
    pause_ms(50);
  CHECK(!atomic_load(&state.done));
  // The waiter must not hold GATE; unrelated FD mutations remain usable.
  int duplicate = dup(fd);
  CHECK(duplicate >= 0 && close(duplicate) == 0);
  if (mode == 0)
    CHECK(foreign_query(fd, holder) == 0);
  if (mode == 1 || mode == 4 || mode == 5 || mode == 6) {
    errno = 123;
    CHECK(pthread_cancel(worker) == 0 && errno == 123);
    if (mode == 6)
      atomic_store_explicit(&state.release, 1, memory_order_release);
  }
  if (mode == 2 || mode == 3) {
    CHECK(pthread_kill(worker, SIGUSR1) == 0);
    CHECK(await(&handled) == 0);
  }
  void *result = NULL;
  if (mode == 1 || mode == 5 || mode == 6) {
    // Join while the child still holds the conflicting lock: cancellation
    // must not depend on the holder releasing its range.
    CHECK(pthread_join(worker, &result) == 0 && result == PTHREAD_CANCELED);
    CHECK(atomic_load(&state.cleaned) == 1 && !atomic_load(&state.done));
  } else if (mode == 2) {
    CHECK(pthread_join(worker, &result) == 0 && result == NULL);
    CHECK(state.result == -1 && state.error == EINTR &&
          !atomic_load(&state.cleaned));
  } else {
    CHECK(!atomic_load(&state.done));
  }
  CHECK(write(go[1], "G", 1) == 1);
  int status;
  CHECK(waitpid(holder, &status, 0) == holder && status == 0);
  if (mode == 0 || mode == 3 || mode == 4) {
    CHECK(pthread_join(worker, &result) == 0);
    CHECK(state.result == 0 && atomic_load(&state.acquired));
    CHECK(result == (mode == 4 ? PTHREAD_CANCELED : NULL));
    CHECK(atomic_load(&state.cleaned) == (mode == 4 ? 1 : 0));
    CHECK(set(fd, F_UNLCK) == 0);
  }
  CHECK(state.setup == 0 && foreign_query(fd, 0) == 0);
  CHECK(close(fd) == 0 && close(ready[0]) == 0 && close(go[1]) == 0 &&
        unlink(path) == 0);
  fprintf(stderr, "wait-lock: PASS mode=%d\n", mode);
  return 0;
}

int main(int argc, char **argv) {
  int result = nonblocking_record_lock_main(argc, argv);
  if (result || (argc == 7 && strcmp(argv[1], "--libc-lock-exec") == 0))
    return result;
  for (int mode = 0; mode < 7; mode++)
    CHECK(run_wait_case(mode) == 0);
  return 0;
}
