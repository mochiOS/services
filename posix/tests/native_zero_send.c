#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { printf("zero-send: FAIL line=%d errno=%d\n", __LINE__, errno); return 1; } } while (0)

static int sends(int fd, int expected_error) {
  struct iovec vector = {NULL, 0};
  struct msghdr message = {0};
  message.msg_iov = &vector; message.msg_iovlen = 1;
  for (int call = 0; call < 4; call++) {
    errno = 0;
    ssize_t result = call == 0 ? send(fd, NULL, 0, MSG_NOSIGNAL | MSG_DONTWAIT)
                   : call == 1 ? write(fd, NULL, 0)
                   : call == 2 ? sendmsg(fd, &message, MSG_NOSIGNAL | MSG_DONTWAIT)
                               : sendto(fd, NULL, 0, MSG_NOSIGNAL | MSG_DONTWAIT, NULL, 0);
    CHECK(expected_error ? result == -1 && errno == expected_error : result == 0);
  }
  return 0;
}

int main(void) {
  CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  CHECK(fd >= 0 && sends(fd, ENOTCONN) == 0 && close(fd) == 0);
  for (int how = SHUT_RD; how <= SHUT_RDWR; how++) {
    int pair[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    CHECK(sends(pair[0], 0) == 0);
    char bytes[1024] = {0};
    while (send(pair[0], bytes, sizeof(bytes), MSG_DONTWAIT | MSG_NOSIGNAL) > 0) {}
    CHECK(errno == EAGAIN && sends(pair[0], 0) == 0);
    CHECK(shutdown(pair[0], how) == 0);
    CHECK(sends(pair[0], how == SHUT_RD ? 0 : EPIPE) == 0);
    if (how != SHUT_WR) CHECK(sends(pair[1], EPIPE) == 0);
    CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
  }
  int pair[2];
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0 && close(pair[1]) == 0);
  CHECK(sends(pair[0], EPIPE) == 0 && close(pair[0]) == 0);
  puts("zero-send: PASS send/write/sendmsg/sendto connection errors, shutdown, peer close and full queues");
  return 0;
}
