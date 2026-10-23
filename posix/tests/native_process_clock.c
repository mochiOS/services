/* Real newlib/POSIX service integration. Run with existing spawn authority. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(test)                                                            \
  do {                                                                         \
    if (!(test)) {                                                             \
      fprintf(stderr, "process-clock: FAIL line=%d errno=%d: %s\n", __LINE__,  \
              errno, #test);                                                   \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static uint64_t nanos(struct timespec t) {
  return (uint64_t)t.tv_sec * 1000000000 + (uint64_t)t.tv_nsec;
}
static volatile sig_atomic_t notified;
static void expired(int signal) {
  if (signal == SIGUSR1)
    ++notified;
}
static int child_probe(clockid_t parent_clock, int notify, int release) {
  clockid_t own;
  CHECK(clock_getcpuclockid(0, &own) == 0 && own != parent_clock);
  struct timespec before, after, parent;
  CHECK(clock_gettime(parent_clock, &parent) == 0);
  CHECK(clock_gettime(own, &before) == 0);
  for (unsigned attempt = 0; attempt < 100; ++attempt) {
    for (volatile unsigned spin = 0; spin < 1000000; ++spin) {
    }
    CHECK(clock_gettime(own, &after) == 0);
    if (nanos(after) > nanos(before))
      break;
  }
  CHECK(nanos(after) > nanos(before));
  CHECK(write(notify, "R", 1) == 1);
  char byte;
  CHECK(read(release, &byte, 1) == 1 && byte == 'X');
  CHECK(clock_gettime(own, &before) == 0);
  do {
    for (volatile unsigned spin = 0; spin < 100000; ++spin) {
    }
    CHECK(clock_gettime(own, &after) == 0);
  } while (nanos(after) - nanos(before) < 100000000);
  CHECK(write(notify, "D", 1) == 1);
  CHECK(read(release, &byte, 1) == 1 && byte == 'Q');
  return 0;
}
int main(void) {
  clockid_t own = 0, again = 0;
  errno = EDOM;
  CHECK(clock_getcpuclockid(0, &own) == 0 && errno == EDOM);
  CHECK(clock_getcpuclockid(getpid(), &again) == 0 && again == own);
  CHECK((uint64_t)own > (UINT64_C(1) << 31) &&
        (uint64_t)own < (UINT64_C(1) << 32));
  CHECK(clock_getcpuclockid(-1, &again) == ESRCH && again == own);
  struct timespec now, quantum;
  CHECK(clock_gettime(own, &now) == 0 && now.tv_nsec < 1000000000);
  CHECK(clock_getres(own, &quantum) == 0 && nanos(quantum) != 0);
  CHECK(clock_getres(own, NULL) == 0);
  struct sigevent none = {.sigev_notify = SIGEV_NONE};
  timer_t self_timer;
  CHECK(timer_create(own, &none, &self_timer) == 0);
  struct itimerspec value = {.it_value = {.tv_nsec = 1}}, remaining;
  CHECK(timer_settime(self_timer, 0, &value, NULL) == 0);
  CHECK(timer_gettime(self_timer, &remaining) == 0);
  CHECK(timer_delete(self_timer) == 0);
  int ready[2], release[2];
  CHECK(pipe(ready) == 0 && pipe(release) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(close(ready[0]) == 0 && close(release[1]) == 0);
    return child_probe(own, ready[1], release[0]);
  }
  CHECK(close(ready[1]) == 0 && close(release[0]) == 0);
  char byte;
  CHECK(read(ready[0], &byte, 1) == 1 && byte == 'R');
  clockid_t foreign = 0;
  errno = EDOM;
  CHECK(clock_getcpuclockid(child, &foreign) == 0 && errno == EDOM);
  CHECK(foreign != own && clock_gettime(foreign, &now) == 0 && nanos(now) != 0);
  CHECK(clock_getres(foreign, &quantum) == 0 && nanos(quantum) != 0);
  struct sigaction action = {.sa_handler = expired}, old_action;
  CHECK(sigemptyset(&action.sa_mask) == 0);
  CHECK(sigaction(SIGUSR1, &action, &old_action) == 0);
  struct sigevent signal = {.sigev_notify = SIGEV_SIGNAL,
                            .sigev_signo = SIGUSR1};
  timer_t foreign_timer;
  CHECK(timer_create(foreign, &signal, &foreign_timer) == 0);
  value.it_value.tv_nsec = 10000000;
  CHECK(timer_settime(foreign_timer, 0, &value, NULL) == 0);
  CHECK(write(release[1], "X", 1) == 1);
  // No timer-get polling: the service reactor must sample the busy child and
  // notify its sleeping parent, rather than measuring the parent's CPU.
  for (unsigned attempt = 0; attempt < 2000 && !notified; ++attempt) {
    struct timespec pause = {.tv_nsec = 1000000};
    int result = nanosleep(&pause, NULL);
    CHECK(result == 0 || (result == -1 && errno == EINTR));
  }
  CHECK(notified == 1);
  CHECK(read(ready[0], &byte, 1) == 1 && byte == 'D');
  CHECK(timer_delete(foreign_timer) == 0);
  CHECK(sigaction(SIGUSR1, &old_action, NULL) == 0);
  CHECK(timer_create(foreign, &none, &foreign_timer) == 0);
  CHECK(write(release[1], "Q", 1) == 1);
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  errno = 0;
  CHECK(clock_gettime(foreign, &now) == -1 && errno == EINVAL);
  errno = EDOM;
  CHECK(clock_getcpuclockid(child, &again) == ESRCH && errno == EDOM &&
        again == own);
  errno = 0;
  CHECK(timer_gettime(foreign_timer, &remaining) == -1 && errno == EINVAL);
  CHECK(timer_delete(foreign_timer) == -1 && errno == EINVAL);
  CHECK(close(ready[0]) == 0 && close(release[1]) == 0);
  fputs("process-clock: PASS self/native, child/service, inherited parent "
        "identity, CPU advancement, resolution, exit invalidation and errno\n",
        stderr);
  fputs("process-clock: PASS selected self/foreign CPU timers, sleeping-owner "
        "signal delivery and subject-exit retirement\n",
        stderr);
  return 0;
}
