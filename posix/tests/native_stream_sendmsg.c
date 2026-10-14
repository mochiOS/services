#define main run_datagram_regressions
#include "native_sendmsg.c"
#undef main

int main(void) {
  CHECK(run_datagram_regressions() == 0);
  int pair[2];
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
  int file = open("/tmp/native-stream-sendmsg", O_CREAT | O_TRUNC | O_RDWR, 0600);
  CHECK(file >= 0 && unlink("/tmp/native-stream-sendmsg") == 0);
  struct iovec vector = {(void *)"bcd", 3};
  union ancillary outgoing;
  struct msghdr request;
  message(&request, &vector, 1, &outgoing, file, 2);
  CHECK(write(pair[0], "aa", 2) == 2);
  CHECK(sendmsg(pair[0], &request, 0) == 3);
  CHECK(write(pair[0], "ee", 2) == 2);
  char output[1024];
  CHECK(recv(pair[1], output, sizeof(output), MSG_PEEK) == 5 && !memcmp(output, "aabcd", 5));
  CHECK(read(pair[1], output, sizeof(output)) == 5 && !memcmp(output, "aabcd", 5));
  CHECK(read(pair[1], output, sizeof(output)) == 2 && !memcmp(output, "ee", 2));
  CHECK(recv(pair[1], output, sizeof(output), MSG_DONTWAIT) == -1 && errno == EAGAIN);
  CHECK(fcntl(file, F_GETFD) == 0);
  for (int cycle = 0; cycle < 6; cycle++) {
    message(&request, &vector, 1, &outgoing, file, 253);
    CHECK(sendmsg(pair[0], &request, 0) == 3);
    CHECK(read(pair[1], output, 1) == 1 && output[0] == 'b');
    CHECK(read(pair[1], output, sizeof(output)) == 2 && !memcmp(output, "cd", 2));
  }
  int capacity = 256;
  CHECK(setsockopt(pair[1], SOL_SOCKET, SO_RCVBUF, &capacity, sizeof(capacity)) == 0);
  memset(output, 'p', 255);
  CHECK(write(pair[0], output, 255) == 255);
  message(&request, &vector, 1, &outgoing, file, 2);
  CHECK(sendmsg(pair[0], &request, 0) == 1);
  CHECK(read(pair[1], output, sizeof(output)) == 256 && output[255] == 'b');
  CHECK(recv(pair[1], output, sizeof(output), MSG_DONTWAIT) == -1 && errno == EAGAIN);
  for (int cycle = 0; cycle < 20; cycle++) {
    message(&request, NULL, 0, &outgoing, file, 253);
    CHECK(sendmsg(pair[0], &request, 0) == 0);
  }
  CHECK(recv(pair[1], output, sizeof(output), MSG_DONTWAIT) == -1 && errno == EAGAIN);

  /* Ancillary slots, not ordinary writable bytes, must gate a blocked send. */
  capacity = 65536;
  CHECK(setsockopt(pair[1], SOL_SOCKET, SO_RCVBUF, &capacity, sizeof(capacity)) == 0);
  vector = (struct iovec){(void *)"x", 1};
  message(&request, &vector, 1, &outgoing, file, 1);
  for (int i = 0; i < 256; i++) CHECK(sendmsg(pair[0], &request, 0) == 1);
  CHECK(sendmsg(pair[0], &request, MSG_DONTWAIT) == -1 && errno == EAGAIN);
  atomic_store(&started, 0); atomic_store(&finished, 0);
  struct send_state state = {pair[0], file, -999, NULL};
  pthread_t thread;
  CHECK(pthread_create(&thread, NULL, blocked_send, &state) == 0);
  while (!atomic_load(&started)) sched_yield();
  struct timespec pause = {0, 30000000};
  CHECK(nanosleep(&pause, NULL) == 0 && !atomic_load(&finished));
  CHECK(read(pair[1], output, 1) == 1);
  CHECK(pthread_join(thread, NULL) == 0 && state.result == 1);
  for (int i = 0; i < 256; i++) CHECK(read(pair[1], output, sizeof(output)) == 1 && output[0] == 'x');
  CHECK(recv(pair[1], output, sizeof(output), MSG_DONTWAIT) == -1 && errno == EAGAIN);
  CHECK(shutdown(pair[1], SHUT_RD) == 0);
  CHECK(sendmsg(pair[0], &request, MSG_NOSIGNAL) == -1 && errno == EPIPE);
  CHECK(close(file) == 0 && close(pair[0]) == 0 && close(pair[1]) == 0);
  puts("stream-sendmsg: PASS native ancillary send, short-prefix commit, ordinary read discard, zero-data cleanup, marker-capacity backpressure and EPIPE");
  fflush(stdout);
  return 0;
}
