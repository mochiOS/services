#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr,                                                          \
              "posix-socket-pair: FAIL line=%u errno=%d condition=%s\n",       \
              __LINE__, errno, #condition);                                    \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static int blocking_fd;
static volatile int started;
static void *reader(void *unused) {
  (void)unused;
  __atomic_store_n(&started, 1, __ATOMIC_RELEASE);
  char byte;
  return read(blocking_fd, &byte, 1) == 1 && byte == 'z' ? NULL : (void *)1;
}
static int verify_exec(char **argv) {
  int a = atoi(argv[2]), b = atoi(argv[3]), closed = atoi(argv[4]);
  CHECK(fcntl(closed, F_GETFD, 0) == -1 && errno == EBADF);
  CHECK(fcntl(a, F_GETFD, 0) == 0 && fcntl(b, F_GETFD, 0) == 0);
  CHECK(fcntl(a, F_GETFL, 0) == (O_RDWR | O_NONBLOCK));
  char bytes[8];
  CHECK(write(b, "exec", 4) == 4);
  CHECK(read(a, bytes, sizeof(bytes)) == 4 && !memcmp(bytes, "exec", 4));
  CHECK(fcntl(a, F_SETFL, 0) == 0);
  fprintf(stderr, "posix-socket-pair-exec: PASS\n");
  return 0;
}
int main(int argc, char **argv) {
  if (argc == 5 && !strcmp(argv[1], "--socket-exec"))
    return verify_exec(argv);
  int fds[2] = {123, 456};
  CHECK(socketpair(AF_UNIX, SOCK_STREAM | 0x1000, 0, fds) == -1 &&
        errno == EINVAL);
  CHECK(fds[0] == 123 && fds[1] == 456);
  struct rlimit original, exhausted;
  CHECK(getrlimit(RLIMIT_NOFILE, &original) == 0);
  exhausted = original;
  exhausted.rlim_cur = 0;
  CHECK(setrlimit(RLIMIT_NOFILE, &exhausted) == 0);
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == -1 && errno == EMFILE);
  CHECK(fds[0] == 123 && fds[1] == 456);
  CHECK(setrlimit(RLIMIT_NOFILE, &original) == 0);
  CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                   fds) == 0);
  int a = fds[0], b = fds[1];
  CHECK(fcntl(a, F_GETFD, 0) == FD_CLOEXEC &&
        fcntl(b, F_GETFD, 0) == FD_CLOEXEC);
  CHECK(fcntl(a, F_GETFL, 0) == (O_RDWR | O_NONBLOCK));
  int alias = dup(a);
  CHECK(alias >= 0 && fcntl(alias, F_GETFD, 0) == 0);
  CHECK(fcntl(alias, F_SETFL, 0) == 0 && fcntl(a, F_GETFL, 0) == O_RDWR);
  CHECK(fcntl(b, F_GETFL, 0) == (O_RDWR | O_NONBLOCK));
  CHECK(fcntl(a, F_SETFL, O_NONBLOCK) == 0);
  char bytes[8];
  CHECK(read(a, bytes, 1) == -1 && errno == EAGAIN);
  CHECK(lseek(a, 0, SEEK_CUR) == -1 && errno == ESPIPE);
  struct pollfd item = {a, POLLIN | POLLOUT | POLLPRI, 0};
  CHECK(poll(&item, 1, 0) == 1 && item.revents == POLLOUT);
  item.events = POLLIN;
  CHECK(poll(&item, 1, 0) == 0 && item.revents == 0);
  CHECK(write(b, "hello", 5) == 5);
  CHECK(poll(&item, 1, 0) == 1 && item.revents == POLLIN);
  fd_set reads, writes, exceptions;
  FD_ZERO(&reads);
  FD_ZERO(&writes);
  FD_ZERO(&exceptions);
  FD_SET(a, &reads);
  FD_SET(a, &writes);
  FD_SET(a, &exceptions);
  struct timeval timeout = {0, 0};
  CHECK(select(a + 1, &reads, &writes, &exceptions, &timeout) == 2);
  CHECK(FD_ISSET(a, &reads) && FD_ISSET(a, &writes) &&
        !FD_ISSET(a, &exceptions));
  CHECK(read(alias, bytes, 3) == 3 && !memcmp(bytes, "hel", 3));
  CHECK(read(a, bytes, 8) == 2 && !memcmp(bytes, "lo", 2));
  CHECK(fcntl(b, F_SETFD, 0) == 0);
  char alias_arg[16], b_arg[16], closed_arg[16];
  snprintf(alias_arg, sizeof(alias_arg), "%d", alias);
  snprintf(b_arg, sizeof(b_arg), "%d", b);
  snprintf(closed_arg, sizeof(closed_arg), "%d", a);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    char *arguments[] = {"socket-test", "--socket-exec", alias_arg,
                         b_arg,         closed_arg,      NULL};
    char *environment[] = {NULL};
    execve("/system/services/compositor.service", arguments, environment);
    _exit(90);
  }
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  CHECK(fcntl(a, F_GETFL, 0) == O_RDWR);
  CHECK(fcntl(a, F_SETFL, O_NONBLOCK) == 0);
  CHECK(shutdown(b, SHUT_WR) == 0);
  CHECK(read(a, bytes, 1) == 0);
  CHECK(write(a, "x", 1) == 1 && read(b, bytes, 1) == 1 && bytes[0] == 'x');
  CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
  CHECK(write(b, "x", 1) == -1 && errno == EPIPE);
  item.fd = b;
  item.events = POLLOUT;
  CHECK(poll(&item, 1, 0) == 1 && item.revents == POLLOUT);
  item.events = 0;
  CHECK(poll(&item, 1, 0) == 0 && item.revents == 0);
  CHECK(close(a) == 0 && close(alias) == 0);
  CHECK(close(b) == 0);
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
  blocking_fd = fds[0];
  pthread_t thread;
  CHECK(pthread_create(&thread, NULL, reader, NULL) == 0);
  while (!__atomic_load_n(&started, __ATOMIC_ACQUIRE))
    sched_yield();
  for (unsigned index = 0; index < 100; ++index)
    sched_yield();
  CHECK(write(fds[1], "z", 1) == 1);
  void *result;
  CHECK(pthread_join(thread, &result) == 0 && result == NULL);
  CHECK(close(fds[0]) == 0 && close(fds[1]) == 0);
  puts("posix-socket-pair: PASS");
  return 0;
}
