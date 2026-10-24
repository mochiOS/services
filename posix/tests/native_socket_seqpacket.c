#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#ifndef MSG_EOR
#define MSG_EOR 0x80
#endif
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "seqpacket: FAIL line=%u errno=%d %s\n", __LINE__,       \
              errno, #x);                                                      \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static volatile sig_atomic_t broken_pipe;
static void on_pipe(int signal_number) {
  if (signal_number == SIGPIPE)
    ++broken_pipe;
}
static int type(int fd) {
  int v = -1;
  socklen_t n = sizeof(v);
  return getsockopt(fd, SOL_SOCKET, SO_TYPE, &v, &n) == 0 && n == sizeof(v) &&
         v == SOCK_SEQPACKET;
}
int main(int argc, char **argv) {
  alarm(90);
  if (argc == 3 && !strcmp(argv[1], "--seq-child")) {
    int fd = atoi(argv[2]);
    CHECK(type(fd));
    CHECK(send(fd, "exec", 4, MSG_EOR) == 4);
    return 0;
  }
  int f[2];
  char data[32] = {0};
  CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, f) == 0);
  CHECK(type(f[0]) && type(f[1]));
  CHECK(send(f[0], "alpha", 5, MSG_EOR) == 5);
  CHECK(send(f[0], "beta", 4, 0) == 4);
  CHECK(recv(f[1], data, 2, MSG_PEEK | MSG_WAITALL) == 2 &&
        !memcmp(data, "al", 2));
  struct iovec vector = {data, 2};
  struct msghdr m = {0};
  m.msg_iov = &vector;
  m.msg_iovlen = 1;
  CHECK(recvmsg(f[1], &m, 0) == 2 && (m.msg_flags & MSG_EOR) &&
        (m.msg_flags & MSG_TRUNC));
  CHECK(recv(f[1], data, sizeof(data), MSG_WAITALL) == 4 &&
        !memcmp(data, "beta", 4));
  CHECK(send(f[0], "", 0, 0) == 0);
  m.msg_flags = 0;
  vector.iov_len = sizeof(data);
  CHECK(recvmsg(f[1], &m, 0) == 0 && (m.msg_flags & MSG_EOR));
  CHECK(recv(f[1], data, sizeof(data), MSG_DONTWAIT) == -1 && errno == EAGAIN);
  puts("seqpacket: PASS type, atomic records, peek, truncation, WAITALL, empty "
       "EOR");
  fflush(stdout);
  struct pollfd watched = {.fd = f[1], .events = POLLIN};
  CHECK(poll(&watched, 1, 0) == 0);
  int alias = dup(f[0]);
  CHECK(alias >= 0 && type(alias));
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    close(f[1]);
    char fd[16];
    snprintf(fd, sizeof(fd), "%d", alias);
    char *args[] = {argv[0], "--seq-child", fd, NULL};
    execv("/system/services/compositor.service", args);
    _exit(99);
  }
  CHECK(recv(f[1], data, sizeof(data), 0) == 4 && !memcmp(data, "exec", 4));
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  CHECK(close(alias) == 0);
  puts("seqpacket: PASS dup, fork and exec retain record type and shared "
       "endpoint");
  fflush(stdout);
  int pipes[2];
  CHECK(pipe(pipes) == 0);
  unsigned char control[CMSG_SPACE(sizeof(int))];
  memset(control, 0, sizeof(control));
  vector.iov_len = 1;
  data[0] = '!';
  m = (struct msghdr){0};
  m.msg_iov = &vector;
  m.msg_iovlen = 1;
  m.msg_control = control;
  m.msg_controllen = sizeof(control);
  struct cmsghdr *c = CMSG_FIRSTHDR(&m);
  c->cmsg_level = SOL_SOCKET;
  c->cmsg_type = SCM_RIGHTS;
  c->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(c), &pipes[0], sizeof(int));
  CHECK(sendmsg(f[0], &m, MSG_EOR) == 1);
  memset(control, 0, sizeof(control));
  m.msg_controllen = sizeof(control);
  CHECK(recvmsg(f[1], &m, 0) == 1 && (m.msg_flags & MSG_EOR));
  c = CMSG_FIRSTHDR(&m);
  CHECK(c && c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS);
  int received = -1;
  memcpy(&received, CMSG_DATA(c), sizeof(int));
  CHECK(write(pipes[1], "R", 1) == 1 && read(received, data, 1) == 1 &&
        data[0] == 'R');
  CHECK(close(received) == 0 && close(pipes[0]) == 0 && close(pipes[1]) == 0);
  CHECK(shutdown(f[0], SHUT_WR) == 0);
  m.msg_control = NULL;
  m.msg_controllen = 0;
  m.msg_flags = 0;
  CHECK(recvmsg(f[1], &m, 0) == 0 && !(m.msg_flags & MSG_EOR));
  CHECK(signal(SIGPIPE, on_pipe) != SIG_ERR);
  CHECK(send(f[0], "x", 1, 0) == -1 && errno == EPIPE);
  CHECK(broken_pipe == 1);
  CHECK(send(f[0], "x", 1, MSG_NOSIGNAL) == -1 && errno == EPIPE);
  CHECK(broken_pipe == 1);
  CHECK(close(f[0]) == 0 && close(f[1]) == 0);
  puts("seqpacket: PASS SCM_RIGHTS, EOF distinct from empty record, shutdown");
  fflush(stdout);
  struct sockaddr_un a = {.sun_family = AF_UNIX};
  strcpy(a.sun_path, "/native-seqpacket-206");
  CHECK(unlink(a.sun_path) == 0 || errno == ENOENT);
  socklen_t size = 2 + strlen(a.sun_path) + 1;
  int listener = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  int client = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  CHECK(listener >= 0 && client >= 0);
  CHECK(bind(listener, (void *)&a, size) == 0 && listen(listener, 4) == 0 &&
        connect(client, (void *)&a, size) == 0);
  int server = accept(listener, NULL, NULL);
  CHECK(server >= 0 && type(server));
  CHECK(write(client, "named", 5) == 5 &&
        read(server, data, sizeof(data)) == 5 && !memcmp(data, "named", 5));
  CHECK(close(client) == 0 && close(server) == 0 && close(listener) == 0 &&
        unlink(a.sun_path) == 0);
  puts("seqpacket: PASS filesystem bind, listen, connect, accept and "
       "read/write");
  fflush(stdout);
  return 0;
}
