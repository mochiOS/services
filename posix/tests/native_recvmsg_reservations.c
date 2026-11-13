/* Native regression: an empty ancillary receive must not consume FD slots
 * while another thread creates a pipe. Also retain the existing SCM_RIGHTS,
 * CLOEXEC, truncation and receipt-reclamation checks. */
#define RECVMSG_TEST_ENTRY run_recvmsg_regressions
#include "native_recvmsg.c"
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>

static atomic_int receivers_ready;
static atomic_int receivers_go;
struct receive_stress { int socket; int error; };

static void *receive_empty(void *opaque) {
  struct receive_stress *state = opaque;
  atomic_fetch_add(&receivers_ready, 1);
  while (!atomic_load(&receivers_go)) sched_yield();
  for (unsigned i = 0; i < 128; ++i) {
    char byte, control[CMSG_SPACE(253 * sizeof(int))];
    struct iovec vector = {&byte, 1};
    struct msghdr message = {NULL, 0, &vector, 1, control, sizeof(control), 0};
    if (recvmsg(state->socket, &message, MSG_DONTWAIT) != -1 || errno != EAGAIN) {
      state->error = 1;
      break;
    }
  }
  return NULL;
}

int main(void) {
  if (!freopen("/tmp/recvmsg-reservations-results.log", "w", stdout)) return 1;
  setvbuf(stdout, NULL, _IOLBF, 0);
  CHECK(dup2(fileno(stdout), 2) == 2);
  CHECK(run_recvmsg_regressions() == 0);
  int pair[2];
  CHECK(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, pair) == 0);
  struct receive_stress state[2] = {{pair[1], 0}, {pair[1], 0}};
  pthread_t threads[2];
  for (unsigned i = 0; i < 2; ++i)
    CHECK(pthread_create(&threads[i], NULL, receive_empty, &state[i]) == 0);
  while (atomic_load(&receivers_ready) != 2) sched_yield();
  atomic_store(&receivers_go, 1);
  for (unsigned i = 0; i < 256; ++i) {
    int pipe_fds[2];
    CHECK(pipe2(pipe_fds, O_CLOEXEC | O_NONBLOCK) == 0);
    CHECK(close(pipe_fds[0]) == 0 && close(pipe_fds[1]) == 0);
    sched_yield();
  }
  for (unsigned i = 0; i < 2; ++i) {
    CHECK(pthread_join(threads[i], NULL) == 0);
    CHECK(state[i].error == 0);
  }
  CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
  puts("RECVMSG-RESERVATIONS PASS");
  fflush(stdout);
  CHECK(fsync(fileno(stdout)) == 0);
  return 0;
}
