#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

static void inspect(int fd, const char *state) {
  errno = 0;
  ssize_t sent = send(fd, NULL, 0, MSG_NOSIGNAL | MSG_DONTWAIT);
  int send_error = errno;
  errno = 0;
  ssize_t received = recv(fd, NULL, 0, MSG_DONTWAIT);
  printf("%s send=%ld/%d recv=%ld/%d\n", state, (long)sent, send_error,
         (long)received, errno);
}
int main(void) {
  signal(SIGPIPE, SIG_IGN);
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return 1;
  inspect(fd, "unconnected");
  close(fd);
  int pair[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) return 1;
  inspect(pair[0], "connected-empty");
  char bytes[4096] = {0};
  while (send(pair[0], bytes, sizeof(bytes), MSG_DONTWAIT | MSG_NOSIGNAL) > 0) {}
  inspect(pair[0], "connected-full");
  shutdown(pair[0], SHUT_WR);
  inspect(pair[0], "write-shutdown");
  close(pair[0]); close(pair[1]);
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) return 1;
  close(pair[1]);
  inspect(pair[0], "peer-closed");
  close(pair[0]);
  return 0;
}
