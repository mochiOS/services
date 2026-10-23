/* Real cancellation of deferred POSIX child/signal IPC calls. */
#define WAIT_ID_ENTRY wait_id_regression
#include "native_wait_id.c"
#undef WAIT_ID_ENTRY
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <time.h>

struct cancel_wait_state {
  int api, mode, result, error, setup, selected;
  pid_t child;
  siginfo_t info;
  sigset_t set;
  atomic_int ready, release, done, cleaned;
};
static void cancel_wait_cleanup(void *pointer) {
  struct cancel_wait_state *state = pointer;
  atomic_fetch_add(&state->cleaned, 1);
}
static void cancel_wait_pause(long milliseconds) {
  struct timespec value = {milliseconds / 1000,
                           (milliseconds % 1000) * 1000000};
  while (nanosleep(&value, &value) < 0 && errno == EINTR) {
  }
}
static int cancel_wait_ready(atomic_int *value) {
  for (int i = 0; i < 5000; i++) {
    if (atomic_load_explicit(value, memory_order_acquire))
      return 0;
    cancel_wait_pause(1);
  }
  return -1;
}
static void *cancel_wait_worker(void *pointer) {
  struct cancel_wait_state *state = pointer;
  pthread_cleanup_push(cancel_wait_cleanup, state);
  if (state->mode == 1)
    state->setup = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
  if (state->mode == 3)
    state->setup = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
  atomic_store_explicit(&state->ready, 1, memory_order_release);
  if (state->mode == 2) {
    while (!atomic_load_explicit(&state->release, memory_order_acquire))
      sched_yield();
  }
  errno = 123;
  switch (state->api) {
  case 0:
    state->result = waitpid(state->child, &state->selected, 0);
    break;
  case 1:
    state->result = waitid(P_PID, state->child, &state->info, WEXITED);
    break;
  case 2:
    state->result = sigwait(&state->set, &state->selected);
    break;
  case 3:
    state->result = sigwaitinfo(&state->set, &state->info);
    break;
  default: {
    struct timespec deadline = {30, 0};
    state->result = sigtimedwait(&state->set, &state->info, &deadline);
    break;
  }
  }
  state->error = errno;
  atomic_store_explicit(&state->done, 1, memory_order_release);
  if (state->mode == 3) {
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL))
      state->setup = 999;
    pthread_testcancel();
  }
  pthread_cleanup_pop(0);
  return NULL;
}

static int service_wait_case(int api, int mode) {
  fprintf(stderr, "service-wait: case api=%d mode=%d\n", api, mode);
  struct cancel_wait_state state = {
      .api = api, .mode = mode, .result = -999, .selected = 99};
  sigemptyset(&state.set);
  sigaddset(&state.set, SIGUSR1);
  sigset_t old;
  CHECK(pthread_sigmask(SIG_BLOCK, &state.set, &old) == 0);
  int release = -1;
  if (api < 2) {
    state.child = held_child(&release);
    CHECK(state.child > 0);
  }
  pthread_t worker;
  CHECK(pthread_create(&worker, NULL, cancel_wait_worker, &state) == 0);
  CHECK(cancel_wait_ready(&state.ready) == 0 && state.setup == 0);
  if (mode != 2)
    cancel_wait_pause(40);
  CHECK(!atomic_load(&state.done));
  if (mode != 4) {
    errno = 111;
    CHECK(pthread_cancel(worker) == 0 && errno == 111);
    if (mode == 2)
      atomic_store_explicit(&state.release, 1, memory_order_release);
  }
  void *result = NULL;
  if (mode < 3) {
    CHECK(pthread_join(worker, &result) == 0 && result == PTHREAD_CANCELED);
    CHECK(atomic_load(&state.cleaned) == 1 && !atomic_load(&state.done));
    // Nothing has completed: the child is still alive or the selected signal
    // has not been sent. Cancellation cannot rely on eventual readiness.
    if (api < 2) {
      int status = 99;
      CHECK(waitpid(state.child, &status, WNOHANG) == 0 && status == 99);
    }
  }
  if (api < 2) {
    CHECK(write(release, "x", 1) == 1 && close(release) == 0);
  } else {
    CHECK(kill(getpid(), SIGUSR1) == 0);
  }
  if (mode >= 3) {
    CHECK(pthread_join(worker, &result) == 0 &&
          result == (mode == 3 ? PTHREAD_CANCELED : NULL));
    CHECK(atomic_load(&state.done) &&
          atomic_load(&state.cleaned) == (mode == 3 ? 1 : 0));
    CHECK(state.error == 123 && state.setup == 0);
    if (api == 0)
      CHECK(state.result == state.child && WIFEXITED(state.selected) &&
            WEXITSTATUS(state.selected) == 37);
    else if (api == 1)
      CHECK(state.result == 0 && state.info.si_pid == state.child &&
            state.info.si_code == CLD_EXITED && state.info.si_status == 37);
    else if (api == 2)
      CHECK(state.result == 0 && state.selected == SIGUSR1);
    else
      CHECK(state.result == SIGUSR1 && state.info.si_signo == SIGUSR1);
  } else if (api < 2) {
    // A second waiter receives the exact status; the cancelled call did not
    // reap it.
    int status;
    CHECK(waitpid(state.child, &status, 0) == state.child &&
          WIFEXITED(status) && WEXITSTATUS(status) == 37);
  } else {
    siginfo_t info;
    struct timespec timeout = {1, 0};
    CHECK(sigtimedwait(&state.set, &info, &timeout) == SIGUSR1 &&
          info.si_signo == SIGUSR1 && info.si_pid == getpid());
  }
  CHECK(pthread_sigmask(SIG_SETMASK, &old, NULL) == 0);
  fprintf(stderr, "service-wait: PASS api=%d mode=%d\n", api, mode);
  return 0;
}

int main(void) {
  CHECK(wait_id_regression() == 0);
  CHECK(alarm(60) == 0);
  for (int api = 0; api < 5; api++)
    for (int mode = 0; mode < 5; mode++)
      CHECK(service_wait_case(api, mode) == 0);
  (void)alarm(0);
  return 0;
}
