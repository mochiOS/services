#define STREAM_RECEIVE_TEST_ENTRY run_stream_receive_regressions
#include "native_stream_recvmsg.c"

static int peek_stream_rights(void) {
  int pair[2];
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
  int file = open("/tmp/native-peek-file", O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
  CHECK(file >= 0 && write(file, "abcdef", 6) == 6 && lseek(file, 0, SEEK_SET) == 0);
  CHECK(unlink("/tmp/native-peek-file") == 0);
  union ancillary outgoing, incoming;
  struct iovec input = {(void *)"bcd", 3};
  struct msghdr request;
  message(&request, &input, 1, &outgoing, file, 2);
  CHECK(write(pair[0], "aa", 2) == 2 && sendmsg(pair[0], &request, 0) == 3);
  CHECK(write(pair[0], "ee", 2) == 2 && close(file) == 0);
  char bytes[16];
  struct iovec output = {bytes, sizeof(bytes)};
  CHECK(recv(pair[1], bytes, sizeof(bytes), MSG_PEEK | MSG_WAITALL) == 5 && !memcmp(bytes, "aabcd", 5));
  struct sockaddr_un source;
  struct msghdr response = {&source, sizeof(source), &output, 1, incoming.bytes, sizeof(incoming), 0};
  CHECK(recvmsg(pair[1], &response, MSG_PEEK) == 5 && !memcmp(bytes, "aabcd", 5));
  CHECK(response.msg_flags == 0 && response.msg_namelen == 0);
  int a = received_fd(&response, 0), b = received_fd(&response, 1);
  CHECK(a >= 0 && b >= 0 && a != b && fcntl(a, F_GETFD) == 0 && fcntl(b, F_GETFD) == 0);
  CHECK(read(a, bytes, 1) == 1 && bytes[0] == 'a' && close(b) == 0);
  response.msg_controllen = sizeof(incoming);
  CHECK(recvmsg(pair[1], &response, MSG_PEEK | MSG_WAITALL | MSG_CMSG_CLOEXEC) == 5 && !memcmp(bytes, "aabcd", 5));
  b = received_fd(&response, 0);
  int c = received_fd(&response, 1);
  CHECK(b >= 0 && c >= 0 && a != b && a != c && b != c);
  CHECK(fcntl(b, F_GETFD) == FD_CLOEXEC && fcntl(c, F_GETFD) == FD_CLOEXEC);
  CHECK(read(b, bytes, 1) == 1 && bytes[0] == 'b');
  CHECK(read(c, bytes, 1) == 1 && bytes[0] == 'c');
  response = (struct msghdr){NULL, 0, &output, 1, NULL, 0, 0};
  CHECK(recvmsg(pair[1], &response, MSG_PEEK | MSG_WAITALL) == 5 && !memcmp(bytes, "aabcd", 5));
  CHECK(response.msg_flags == MSG_CTRUNC && response.msg_controllen == 0);
  /* Zero-length stream peeks must not acquire or discard queued references. */
  response = (struct msghdr){NULL, 0, NULL, 0, incoming.bytes, sizeof(incoming), 0};
  CHECK(recvmsg(pair[1], &response, MSG_PEEK | MSG_WAITALL) == 0 && response.msg_controllen == 0 && response.msg_flags == 0);
  /* Consume through ordinary read; previously delivered references stay live. */
  CHECK(read(pair[1], bytes, sizeof(bytes)) == 5 && !memcmp(bytes, "aabcd", 5));
  CHECK(read(pair[1], bytes, sizeof(bytes)) == 2 && !memcmp(bytes, "ee", 2));
  CHECK(read(a, bytes, 1) == 1 && bytes[0] == 'd');
  CHECK(close(a) == 0 && close(b) == 0 && close(c) == 0);
  CHECK(shutdown(pair[0], SHUT_WR) == 0);
  response = (struct msghdr){NULL, 0, &output, 1, incoming.bytes, sizeof(incoming), 0};
  CHECK(recvmsg(pair[1], &response, MSG_PEEK | MSG_WAITALL) == 0 && response.msg_controllen == 0 && response.msg_flags == 0);
  CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
  return 0;
}

static int peek_datagram_rights(void) {
  int pair[2];
  CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0);
  int file = open("/tmp/native-peek-dgram", O_CREAT | O_TRUNC | O_RDWR, 0600);
  CHECK(file >= 0 && write(file, "q", 1) == 1 && unlink("/tmp/native-peek-dgram") == 0);
  union ancillary outgoing, incoming;
  struct iovec input = {(void *)"abc", 3};
  struct msghdr request;
  message(&request, &input, 1, &outgoing, file, 2);
  CHECK(sendmsg(pair[0], &request, 0) == 3);
  char bytes[8];
  struct iovec output = {bytes, 1};
  for (int i = 0; i < 24; i++) {
    /* Capacity for exactly one FD; truncating a peek must retain both queued FDs. */
    struct msghdr response = {NULL, 0, &output, 1, incoming.bytes, CMSG_LEN(sizeof(int)), 0};
    CHECK(recvmsg(pair[1], &response, MSG_PEEK | MSG_TRUNC | MSG_CMSG_CLOEXEC | (i % 2 ? MSG_WAITALL : 0)) == 3 && bytes[0] == 'a');
    CHECK(response.msg_flags == (MSG_TRUNC | MSG_CTRUNC));
    int fd = received_fd(&response, 0);
    CHECK(fd >= 0 && fcntl(fd, F_GETFD) == FD_CLOEXEC && pread(fd, bytes, 1, 0) == 1 && bytes[0] == 'q');
    CHECK(close(fd) == 0);
  }
  output.iov_len = sizeof(bytes);
  struct msghdr response = {NULL, 0, &output, 1, incoming.bytes, sizeof(incoming), 0};
  CHECK(recvmsg(pair[1], &response, 0) == 3 && !memcmp(bytes, "abc", 3) && response.msg_flags == 0);
  int a = received_fd(&response, 0), b = received_fd(&response, 1);
  CHECK(a >= 0 && b >= 0 && a != b && close(a) == 0 && close(b) == 0);
  /* Empty records still carry rights, unlike zero-length stream reads. */
  input.iov_len = 0;
  CHECK(sendmsg(pair[0], &request, 0) == 0 && close(file) == 0);
  for (int i = 0; i < 2; i++) {
    response = (struct msghdr){NULL, 0, NULL, 0, incoming.bytes, sizeof(incoming), 0};
    CHECK(recvmsg(pair[1], &response, MSG_PEEK) == 0 && response.msg_flags == 0);
    a = received_fd(&response, 0); b = received_fd(&response, 1);
    CHECK(a >= 0 && b >= 0 && a != b && close(a) == 0 && close(b) == 0);
  }
  response = (struct msghdr){NULL, 0, NULL, 0, incoming.bytes, sizeof(incoming), 0};
  CHECK(recvmsg(pair[1], &response, 0) == 0 && response.msg_flags == 0);
  a = received_fd(&response, 0); b = received_fd(&response, 1);
  CHECK(a >= 0 && b >= 0 && a != b && close(a) == 0 && close(b) == 0);
  response.msg_controllen = sizeof(incoming);
  CHECK(recvmsg(pair[1], &response, MSG_PEEK | MSG_DONTWAIT) == -1 && errno == EAGAIN);
  CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
  return 0;
}

static int peek_waitall_prefix(void) {
  for (int mode = 0; mode < 3; mode++) {
    int pair[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    CHECK(write(pair[0], "aa", 2) == 2);
    char bytes[8];
    union ancillary control;
    struct iovec output = {bytes, sizeof(bytes)};
    struct msghdr response = {NULL, 0, &output, 1, mode == 1 ? NULL : control.bytes,
                              mode == 1 ? 0 : sizeof(control), 0};
    ssize_t count = mode == 2 ? recv(pair[1], bytes, sizeof(bytes), MSG_PEEK | MSG_WAITALL)
                             : recvmsg(pair[1], &response, MSG_PEEK | MSG_WAITALL);
    CHECK(count == 2 && !memcmp(bytes, "aa", 2));
    CHECK(mode == 2 || (response.msg_controllen == 0 && response.msg_flags == 0));
    CHECK(read(pair[1], bytes, sizeof(bytes)) == 2 && !memcmp(bytes, "aa", 2));
    struct timeval timeout = {0, 8000};
    CHECK(setsockopt(pair[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    response.msg_controllen = mode == 1 ? 0 : sizeof(control);
    count = mode == 2 ? recv(pair[1], bytes, sizeof(bytes), MSG_PEEK | MSG_WAITALL)
                     : recvmsg(pair[1], &response, MSG_PEEK | MSG_WAITALL);
    CHECK(count == -1 && errno == EAGAIN);
    timeout.tv_usec = 0;
    CHECK(setsockopt(pair[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    struct writer_state state = {pair[0], 0, -999};
    pthread_t thread;
    atomic_store(&started, 0); atomic_store(&finished, 0);
    CHECK(pthread_create(&thread, NULL, writer, &state) == 0);
    response.msg_controllen = mode == 1 ? 0 : sizeof(control);
    count = mode == 2 ? recv(pair[1], bytes, sizeof(bytes), MSG_PEEK | MSG_WAITALL)
                     : recvmsg(pair[1], &response, MSG_PEEK | MSG_WAITALL);
    CHECK(count == 4 && !memcmp(bytes, "cdef", 4));
    CHECK(pthread_join(thread, NULL) == 0 && state.result == 4);
    CHECK(read(pair[1], bytes, sizeof(bytes)) == 4 && !memcmp(bytes, "cdef", 4));
    CHECK(close(pair[0]) == 0);
    response.msg_controllen = mode == 1 ? 0 : sizeof(control);
    count = mode == 2 ? recv(pair[1], bytes, sizeof(bytes), MSG_PEEK | MSG_WAITALL)
                     : recvmsg(pair[1], &response, MSG_PEEK | MSG_WAITALL);
    CHECK(count == 0);
    CHECK(close(pair[1]) == 0);
  }
  puts("peek-waitall: PASS host-matched available prefixes, FD barriers, empty-queue timeout, delayed data and EOF for recv/recvmsg");
  return 0;
}

#ifndef PEEK_RECEIVE_TEST_ENTRY
#define PEEK_RECEIVE_TEST_ENTRY main
#endif
int PEEK_RECEIVE_TEST_ENTRY(void) {
  CHECK(run_stream_receive_regressions() == 0);
  CHECK(peek_stream_rights() == 0);
  CHECK(peek_datagram_rights() == 0);
  CHECK(peek_waitall_prefix() == 0);
  puts("peek-recvmsg: PASS repeated stream/datagram FD peeks, independent receiver references, shared/unlinked OFD, CLOEXEC, ancillary barriers, truncation, empty records and EOF");
  return 0;
}
