/* Run with matching posix.service and newlib runtime; does not grant new
 * filesystem authority or rely on a synthetic /dev/pts pathname. The terminal
 * SID must remain stable when its foreground process group changes. */
#include <errno.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                         \
      fprintf(stderr, "terminal-session: FAIL line=%d errno=%d\n", __LINE__,    \
              errno);                                                          \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static int foreground_group_is_not_session(int fd, pid_t session) {
  int ready[2], finish[2];
  CHECK(pipe(ready) == 0 && pipe(finish) == 0);
  pid_t member = fork();
  CHECK(member >= 0);
  if (member == 0) {
    close(ready[0]);
    close(finish[1]);
    if (setpgid(0, 0) != 0 || write(ready[1], "r", 1) != 1)
      _exit(2);
    char value;
    _exit(read(finish[0], &value, 1) == 1 && value == 'f' ? 0 : 3);
  }
  CHECK(close(ready[1]) == 0 && close(finish[0]) == 0);
  char value;
  CHECK(read(ready[0], &value, 1) == 1 && value == 'r');
  sigset_t blocked, previous;
  CHECK(sigemptyset(&blocked) == 0 && sigaddset(&blocked, SIGTTOU) == 0);
  CHECK(sigprocmask(SIG_BLOCK, &blocked, &previous) == 0);
  CHECK(member != session && tcsetpgrp(fd, member) == 0);
  CHECK(tcgetpgrp(fd) == member);
  CHECK(tcgetsid(fd) == session);
  CHECK(tcsetpgrp(fd, getpgrp()) == 0);
  CHECK(sigprocmask(SIG_SETMASK, &previous, NULL) == 0);
  CHECK(write(finish[1], "f", 1) == 1);
  int status;
  CHECK(waitpid(member, &status, 0) == member);
  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  CHECK(close(ready[0]) == 0 && close(finish[1]) == 0);
  return 0;
}

static int controller(int master, int slave, int ready, int finish) {
  CHECK(close(master) == 0);
  CHECK(login_tty(slave) == 0);
  pid_t session = getsid(0);
  CHECK(session > 0 && session == getpid());
  for (int fd = 0; fd < 3; ++fd) {
    CHECK(tcgetsid(fd) == session);
  }
  CHECK(tcgetpgrp(0) == getpgrp());
  CHECK(foreground_group_is_not_session(0, session) == 0);
  CHECK(write(ready, "r", 1) == 1);
  char value;
  CHECK(read(finish, &value, 1) == 1 && value == 'f');
  return 0;
}

int main(void) {
  int master, slave, ready[2], finish[2];
  CHECK(openpty(&master, &slave, NULL, NULL, NULL) == 0);
  errno = 0;
  CHECK(tcgetsid(-1) == -1 && errno == EBADF);
  errno = 0;
  CHECK(tcgetsid(slave) == -1 && errno == ENOTTY);
  CHECK(pipe(ready) == 0 && pipe(finish) == 0);
  errno = 0;
  CHECK(tcgetsid(ready[0]) == -1 && errno == ENOTTY);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    close(ready[0]);
    close(finish[1]);
    _exit(controller(master, slave, ready[1], finish[0]));
  }
  CHECK(close(ready[1]) == 0 && close(finish[0]) == 0);
  char value;
  CHECK(read(ready[0], &value, 1) == 1 && value == 'r');
  /* Holding the same slave Handle does not put this process in the child's
   * controlling session. Handle authority alone must not disclose its SID. */
  errno = 0;
  CHECK(tcgetsid(slave) == -1 && errno == ENOTTY);
  CHECK(write(finish[1], "f", 1) == 1);
  int status;
  CHECK(waitpid(child, &status, 0) == child);
  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  CHECK(close(ready[0]) == 0 && close(finish[1]) == 0);
  CHECK(close(master) == 0 && close(slave) == 0);
  puts("terminal-session: PASS");
  return 0;
}
