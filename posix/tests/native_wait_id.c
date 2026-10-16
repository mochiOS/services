/* Real libc -> guarded IPC -> POSIX wait state -> siginfo publication. */
#define main directory_baseline_main
#include "native_directory_io.c"
#undef main
#include <signal.h>
#include <sys/wait.h>

static pid_t held_child(int *release) {
  int gate[2], ready[2];
  if (pipe(gate) || pipe(ready))
    return -1;
  pid_t child = fork();
  if (child == 0) {
    close(gate[1]);
    close(ready[0]);
    char byte = 'x';
    if (write(ready[1], &byte, 1) != 1 || read(gate[0], &byte, 1) != 1)
      _exit(91);
    _exit(37);
  }
  close(gate[0]);
  close(ready[1]);
  char byte;
  if (child < 0 || read(ready[0], &byte, 1) != 1)
    return -1;
  close(ready[0]);
  *release = gate[1];
  return child;
}

int main(void) {
  _Static_assert(sizeof(siginfo_t) == 40, "waitid siginfo ABI");
  siginfo_t info;
  int release;
  pid_t child = held_child(&release);
  CHECK(child > 0);
  memset(&info, 0xff, sizeof(info));
  CHECK(waitid(P_PID, child, &info, WEXITED | WNOHANG) == 0);
  CHECK(info.si_pid == 0 && info.si_signo == 0 && info.si_code == 0);
  errno = 0;
  CHECK(waitid(P_PID, child, &info, WNOWAIT) == -1 && errno == EINVAL);
  errno = 0;
  CHECK(waitid(P_PID, 0, &info, WEXITED) == -1 && errno == EINVAL);
  if (getpgrp() != 1) {
    errno = 0;
    CHECK(waitid(P_PGID, 1, &info, WEXITED | WNOHANG) == -1 && errno == ECHILD);
  }
  CHECK(write(release, "x", 1) == 1 && close(release) == 0);
  CHECK(waitid(P_PID, child, &info, WEXITED | WNOWAIT) == 0);
  CHECK(info.si_signo == SIGCHLD && info.si_code == CLD_EXITED &&
        info.si_pid == child);
  CHECK(info.si_uid == getuid() && info.si_status == 37);
  errno = 0;
  CHECK(waitid(P_PID, child, (siginfo_t *)(uintptr_t)1, WEXITED | WNOWAIT) ==
            -1 &&
        errno == EFAULT);
  CHECK(waitid(P_ALL, 0, &info, WEXITED | WNOWAIT) == 0 &&
        info.si_pid == child && info.si_status == 37);
  CHECK(waitid(P_PGID, 0, &info, WEXITED) == 0 && info.si_pid == child);
  errno = 0;
  CHECK(waitpid(child, NULL, WNOHANG) == -1 && errno == ECHILD);

  child = held_child(&release);
  CHECK(child > 0 && kill(child, SIGSTOP) == 0);
  CHECK(waitid(P_PID, child, &info, WSTOPPED | WNOWAIT) == 0);
  CHECK(info.si_code == CLD_STOPPED && info.si_status == SIGSTOP &&
        info.si_pid == child);
  CHECK(waitid(P_PID, child, &info, WSTOPPED | WNOWAIT) == 0 &&
        info.si_code == CLD_STOPPED);
  int status;
  CHECK(waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status));
  CHECK(kill(child, SIGCONT) == 0);
  CHECK(waitid(P_PID, child, &info, WCONTINUED | WNOWAIT) == 0);
  CHECK(info.si_code == CLD_CONTINUED && info.si_status == SIGCONT);
  CHECK(waitid(P_PID, child, &info, WCONTINUED) == 0 &&
        info.si_code == CLD_CONTINUED);
  CHECK(kill(child, SIGTERM) == 0);
  CHECK(waitid(P_PID, child, &info, WEXITED) == 0);
  CHECK(info.si_code == CLD_KILLED && info.si_status == SIGTERM &&
        info.si_pid == child);
  CHECK(close(release) == 0);
  puts("wait-id: PASS selectors, NOHANG, NOWAIT, siginfo, faults, "
       "stop/continue and termination");
  return 0;
}
