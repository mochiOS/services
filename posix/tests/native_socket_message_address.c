#define SOCKET_PEEK_TEST_ENTRY run_peek_regressions
#include "native_socket_peek.c"
#undef CHECK

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "socket-address: FAIL line=%u errno=%d %s\n", __LINE__,  \
              errno, #x);                                                      \
      return 1;                                                                \
    }                                                                          \
  } while (0)

int main(int argc, char **argv) {
  if (argc == 5 && !strcmp(argv[1], "--socket-exec"))
    return run_peek_regressions(argc, argv);
  int sockets[2];
  char bytes[8] = {0};
  unsigned char expected[110], address[110];
  socklen_t expected_length = sizeof(expected), length;
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
  CHECK(getpeername(sockets[1], (struct sockaddr *)expected,
                    &expected_length) == 0);
  CHECK(expected_length > 0 && expected_length <= sizeof(expected));
  CHECK(sendto(sockets[0], "abc", 3, 0, (void *)(uintptr_t)1, (socklen_t)-1) ==
        3);
  // Invalid output metadata cannot consume queued bytes.
  CHECK(recvfrom(sockets[1], bytes, 3, 0, (struct sockaddr *)address, NULL) ==
            -1 &&
        errno == EFAULT);
  for (unsigned int capacity = 0; capacity <= expected_length + 1; capacity++) {
    memset(address, 0x55, sizeof(address));
    length = capacity;
    CHECK(recvfrom(sockets[1], bytes, 3, MSG_PEEK | MSG_WAITALL,
                   (struct sockaddr *)address, &length) == 3);
    CHECK(!memcmp(bytes, "abc", 3) && length == expected_length);
    unsigned int copied =
        capacity < expected_length ? capacity : expected_length;
    CHECK(!memcmp(address, expected, copied));
    for (unsigned int i = copied; i < sizeof(address); i++)
      CHECK(address[i] == 0x55);
  }
  CHECK(recvfrom(sockets[1], bytes, 3, MSG_WAITALL, NULL,
                 (void *)(uintptr_t)1) == 3 &&
        !memcmp(bytes, "abc", 3));
  memset(address, 0x55, sizeof(address));
  length = sizeof(address);
  CHECK(recvfrom(sockets[1], bytes, 1, MSG_DONTWAIT, (struct sockaddr *)address,
                 &length) == -1 &&
        errno == EAGAIN);
  CHECK(length == sizeof(address));
  for (unsigned int i = 0; i < sizeof(address); i++)
    CHECK(address[i] == 0x55);
  CHECK(sendto(sockets[0], "x", 1, MSG_PEEK, NULL, 0) == -1 &&
        errno == EOPNOTSUPP);
  CHECK(shutdown(sockets[0], SHUT_WR) == 0);
  CHECK(recvfrom(sockets[1], bytes, 1, 0, (struct sockaddr *)address,
                 &length) == 0);
  CHECK(length == expected_length && !memcmp(address, expected, length));
  CHECK(sendto(sockets[0], "x", 1, MSG_NOSIGNAL, NULL, 0) == -1 &&
        errno == EPIPE);
  CHECK(close(sockets[0]) == 0 && close(sockets[1]) == 0);
  CHECK(sendto(-1, bytes, 1, 0, NULL, 0) == -1 && errno == EBADF);
  CHECK(recvfrom(-1, bytes, 1, 0, NULL, NULL) == -1 && errno == EBADF);
  puts("socket-address: PASS stream sendto/recvfrom, truncation, peek, errors, "
       "EOF");
  fflush(stdout);
  return run_peek_regressions(argc, argv);
}
