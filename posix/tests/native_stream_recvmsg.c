#define STREAM_SEND_TEST_ENTRY run_stream_send_regressions
#include "native_stream_sendmsg.c"
#include <sys/time.h>

struct writer_state { int socket, mode; ssize_t result; };
static void *writer(void *opaque) {
  struct writer_state *state = opaque;
  atomic_store(&started, 1);
  if (state->mode != 1) {
    struct timespec delay = {0, state->mode == 2 ? 100000000 : 30000000};
    if (nanosleep(&delay, NULL) != 0) { state->result = -1; return NULL; }
  }
  if (state->mode == 2) {
    state->result = write(state->socket, "c", 1);
    struct timespec delay = {0, 150000000};
    if (state->result == 1 && nanosleep(&delay, NULL) == 0)
      state->result += write(state->socket, "def", 3);
  } else {
    state->result = write(state->socket, state->mode == 1 ? "z" : "cdef", state->mode == 1 ? 1 : 4);
  }
  atomic_store(&finished, 1);
  return NULL;
}

#ifndef STREAM_RECEIVE_TEST_ENTRY
#define STREAM_RECEIVE_TEST_ENTRY main
#endif
int STREAM_RECEIVE_TEST_ENTRY(void) {
  CHECK(run_stream_send_regressions() == 0);
  int pair[2];
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
  int file = open("/tmp/native-stream-recvmsg", O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
  CHECK(file >= 0 && write(file, "abcdefgh", 8) == 8 && lseek(file, 0, SEEK_SET) == 0);
  CHECK(unlink("/tmp/native-stream-recvmsg") == 0);
  struct iovec input = {(void *)"bcd", 3};
  union ancillary outgoing, incoming;
  struct msghdr request;
  message(&request, &input, 1, &outgoing, file, 2);
  CHECK(write(pair[0], "aa", 2) == 2 && sendmsg(pair[0], &request, 0) == 3);
  CHECK(write(pair[0], "ee", 2) == 2 && close(file) == 0);
  unsigned char first[2], second[14];
  struct iovec output[] = {{first, 2}, {second, sizeof(second)}};
  struct sockaddr_un source;
  memset(&source, 0xa5, sizeof(source));
  struct msghdr response = {&source, sizeof(source), output, 2, incoming.bytes, sizeof(incoming), 0};
  CHECK(recvmsg(pair[1], &response, MSG_WAITALL | MSG_CMSG_CLOEXEC) == 5);
  CHECK(!memcmp(first, "aa", 2) && !memcmp(second, "bcd", 3));
  CHECK(response.msg_flags == 0 && response.msg_namelen == 0 && ((unsigned char *)&source)[0] == 0xa5);
  int a = received_fd(&response, 0), b = received_fd(&response, 1);
  CHECK(a >= 0 && b >= 0 && a != b && fcntl(a, F_GETFD) == FD_CLOEXEC && fcntl(b, F_GETFD) == FD_CLOEXEC);
  CHECK(read(a, first, 1) == 1 && first[0] == 'a');
  CHECK(read(b, first, 1) == 1 && first[0] == 'b' && close(b) == 0);
  file = a;
  CHECK(read(pair[1], second, sizeof(second)) == 2 && !memcmp(second, "ee", 2));

  message(&request, &input, 1, &outgoing, file, 1);
  CHECK(write(pair[0], "aa", 2) == 2 && sendmsg(pair[0], &request, 0) == 3 && write(pair[0], "ee", 2) == 2);
  struct iovec short_output = {second, 3};
  response = (struct msghdr){NULL, 0, &short_output, 1, incoming.bytes, sizeof(incoming), 0};
  CHECK(recvmsg(pair[1], &response, 0) == 3 && !memcmp(second, "aab", 3));
  CHECK(close(received_fd(&response, 0)) == 0);
  short_output.iov_len = sizeof(second);
  response.msg_controllen = sizeof(incoming);
  CHECK(recvmsg(pair[1], &response, MSG_DONTWAIT) == 4 && !memcmp(second, "cdee", 4));
  CHECK(response.msg_controllen == 0 && response.msg_flags == 0);
  CHECK(sendmsg(pair[0], &request, 0) == 3);
  response = (struct msghdr){NULL, 0, NULL, 0, incoming.bytes, sizeof(incoming), 0};
  CHECK(recvmsg(pair[1], &response, 0) == 0 && response.msg_controllen == 0);
  response = (struct msghdr){NULL, 0, &short_output, 1, incoming.bytes, sizeof(incoming), 0};
  CHECK(recvmsg(pair[1], &response, 0) == 3 && !memcmp(second, "bcd", 3));
  CHECK(close(received_fd(&response, 0)) == 0);
  for (size_t capacity = 0; capacity <= 40; capacity++) {
    message(&request, &input, 1, &outgoing, file, 4);
    CHECK(sendmsg(pair[0], &request, 0) == 3);
    memset(&incoming, 0xa5, sizeof(incoming));
    response = (struct msghdr){NULL, 0, &short_output, 1, incoming.bytes, capacity, 0};
    CHECK(recvmsg(pair[1], &response, MSG_WAITALL) == 3 && !memcmp(second, "bcd", 3));
    size_t count = capacity < CMSG_LEN(sizeof(int)) ? 0 : (capacity - CMSG_LEN(0)) / sizeof(int);
    if (count > 4) count = 4;
    CHECK(response.msg_flags == (count < 4 ? MSG_CTRUNC : 0));
    for (size_t i = 0; i < count; i++) {
      int fd = received_fd(&response, i);
      CHECK(fd >= 0 && fcntl(fd, F_GETFD) == 0 && close(fd) == 0);
    }
    CHECK(incoming.bytes[capacity] == 0xa5);
  }
  for (int cycle = 0; cycle < 6; cycle++) {
    message(&request, &input, 1, &outgoing, file, 253);
    CHECK(sendmsg(pair[0], &request, 0) == 3);
    response = (struct msghdr){NULL, 0, &short_output, 1, incoming.bytes, sizeof(incoming), 0};
    CHECK(recvmsg(pair[1], &response, 0) == 3 && response.msg_flags == MSG_CTRUNC);
    struct cmsghdr *header = CMSG_FIRSTHDR(&response);
    CHECK(header && header->cmsg_type == SCM_RIGHTS && header->cmsg_level == SOL_SOCKET);
    size_t count = (header->cmsg_len - CMSG_LEN(0)) / sizeof(int);
    CHECK(count > 0 && count < 253);
    for (size_t i = 0; i < count; i++) CHECK(close(received_fd(&response, i)) == 0);
  }

  CHECK(write(pair[0], "ab", 2) == 2);
  atomic_store(&started, 0); atomic_store(&finished, 0);
  struct writer_state state = {pair[0], 0, -999};
  pthread_t thread;
  CHECK(pthread_create(&thread, NULL, writer, &state) == 0);
  output[1].iov_len = 4;
  response = (struct msghdr){NULL, 0, output, 2, incoming.bytes, sizeof(incoming), 0};
  CHECK(recvmsg(pair[1], &response, MSG_WAITALL) == 6);
  CHECK(!memcmp(first, "ab", 2) && !memcmp(second, "cdef", 4) && response.msg_controllen == 0);
  CHECK(pthread_join(thread, NULL) == 0 && state.result == 4);
  /* Timeout is per call, not restarted after every plain prefix. */
  struct timeval timeout = {0, 200000};
  CHECK(setsockopt(pair[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
  CHECK(write(pair[0], "ab", 2) == 2);
  state = (struct writer_state){pair[0], 2, -999};
  CHECK(pthread_create(&thread, NULL, writer, &state) == 0);
  response.msg_controllen = sizeof(incoming);
  CHECK(recvmsg(pair[1], &response, MSG_WAITALL) == 3);
  CHECK(first[0] == 'a' && first[1] == 'b' && second[0] == 'c');
  CHECK(pthread_join(thread, NULL) == 0 && state.result == 4);
  timeout = (struct timeval){0, 0};
  CHECK(setsockopt(pair[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
  CHECK(read(pair[1], second, sizeof(second)) == 3 && !memcmp(second, "def", 3));

  /* A recvmsg drain must wake an ordinary native HandleWrite waiter too. */
  int capacity = 256;
  CHECK(setsockopt(pair[1], SOL_SOCKET, SO_RCVBUF, &capacity, sizeof(capacity)) == 0);
  static unsigned char full[256];
  CHECK(write(pair[0], full, sizeof(full)) == sizeof(full));
  state = (struct writer_state){pair[0], 1, -999};
  atomic_store(&started, 0); atomic_store(&finished, 0);
  CHECK(pthread_create(&thread, NULL, writer, &state) == 0);
  while (!atomic_load(&started)) sched_yield();
  struct timespec delay = {0, 30000000};
  CHECK(nanosleep(&delay, NULL) == 0 && !atomic_load(&finished));
  short_output.iov_len = 1;
  response = (struct msghdr){NULL, 0, &short_output, 1, NULL, 0, 0};
  CHECK(recvmsg(pair[1], &response, 0) == 1);
  CHECK(pthread_join(thread, NULL) == 0 && state.result == 1);
  unsigned char rest[256];
  CHECK(read(pair[1], rest, sizeof(rest)) == sizeof(rest) && rest[255] == 'z');
  CHECK(write(pair[0], "ab", 2) == 2 && shutdown(pair[0], SHUT_WR) == 0);
  response = (struct msghdr){NULL, 0, output, 2, incoming.bytes, sizeof(incoming), 0};
  CHECK(recvmsg(pair[1], &response, MSG_WAITALL) == 2 && !memcmp(first, "ab", 2));
  CHECK(recvmsg(pair[1], &response, 0) == 0);
  CHECK(close(file) == 0 && close(pair[0]) == 0 && close(pair[1]) == 0);
  puts("stream-recvmsg: PASS native FD delivery, shared OFD, CLOEXEC, ancillary barriers, control/FD truncation, zero read, WAITALL timeout/EOF and native writer wakeup");
  fflush(stdout);
  return 0;
}
