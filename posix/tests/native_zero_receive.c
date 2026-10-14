#define PEEK_RECEIVE_TEST_ENTRY run_message_regressions
#include "native_peek_recvmsg.c"

static atomic_int zero_started, zero_finished;
struct zero_receive_state { int fd, api; ssize_t result; };

static ssize_t zero_receive(int fd, int api, int flags) {
  if (api == 0) return recv(fd, (void *)1, 0, flags);
  if (api == 1) return recvfrom(fd, (void *)1, 0, flags, NULL, NULL);
  unsigned char control[64];
  struct msghdr message = {NULL, 0, NULL, 0, control, sizeof(control), 0x777};
  ssize_t result = recvmsg(fd, &message, flags);
  if (result == 0 && (message.msg_controllen != 0 || message.msg_flags != 0)) {
    errno = EINVAL;
    return -2;
  }
  return result;
}

static void *zero_reader(void *opaque) {
  struct zero_receive_state *state = opaque;
  atomic_store(&zero_started, 1);
  state->result = zero_receive(state->fd, state->api, MSG_WAITALL);
  atomic_store(&zero_finished, 1);
  return NULL;
}

int main(void) {
#ifndef ZERO_RECEIVE_ONLY
  CHECK(run_message_regressions() == 0);
#endif
  for (int api = 0; api < 3; api++) {
    for (int mode = 0; mode < 4; mode++) {
      int pair[2]; char byte;
      int flags = (mode & 1 ? MSG_PEEK : 0) | (mode & 2 ? MSG_WAITALL : 0);
      CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
      CHECK(read(pair[1], NULL, 0) == 0);
      CHECK(zero_receive(pair[1], api, flags | MSG_DONTWAIT) == -1 && errno == EAGAIN);
      CHECK(fcntl(pair[1], F_SETFL, O_NONBLOCK) == 0);
      CHECK(zero_receive(pair[1], api, flags) == -1 && errno == EAGAIN);
      CHECK(fcntl(pair[1], F_SETFL, 0) == 0);
      struct timeval timeout = {0, 20000};
      CHECK(setsockopt(pair[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
      CHECK(zero_receive(pair[1], api, flags) == -1 && errno == EAGAIN);
      timeout = (struct timeval){0, 0};
      CHECK(setsockopt(pair[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
      CHECK(write(pair[0], "x", 1) == 1);
      CHECK(zero_receive(pair[1], api, flags) == 0);
      CHECK(read(pair[1], &byte, 1) == 1 && byte == 'x');
      CHECK(shutdown(pair[0], SHUT_WR) == 0);
      CHECK(zero_receive(pair[1], api, flags) == 0);
      CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
    }
    for (int eof = 0; eof < 2; eof++) {
      int pair[2]; char byte;
      CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
      atomic_store(&zero_started, 0); atomic_store(&zero_finished, 0);
      struct zero_receive_state state = {pair[1], api, -999};
      pthread_t reader;
      CHECK(pthread_create(&reader, NULL, zero_reader, &state) == 0);
      while (!atomic_load(&zero_started)) sched_yield();
      struct timespec delay = {0, 30000000};
      CHECK(nanosleep(&delay, NULL) == 0 && !atomic_load(&zero_finished));
      if (eof) CHECK(shutdown(pair[0], SHUT_WR) == 0);
      else CHECK(write(pair[0], "y", 1) == 1);
      CHECK(pthread_join(reader, NULL) == 0 && state.result == 0);
      if (!eof) CHECK(read(pair[1], &byte, 1) == 1 && byte == 'y');
      CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
    }
  }
  puts("zero-receive: PASS recv/recvfrom/recvmsg nonblocking, timeouts, data/EOF wakeups and nonconsumption");
  return 0;
}
