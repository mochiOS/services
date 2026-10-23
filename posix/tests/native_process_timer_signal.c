/* Native integration probe: must run on mochiOS. Host linking alone does not
 * verify the reactor, inherited endpoint or ThreadInterrupt/upcall boundary.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define CHECK(test)                                                             \
  do {                                                                          \
    if (!(test)) {                                                              \
      fprintf(stderr, "timer-signal: FAIL line=%d errno=%d: %s\n", __LINE__,     \
              errno, #test);                                                   \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static volatile sig_atomic_t caught, invalid;
static const uintptr_t marker = UINT64_C(0x1234567876543210);
static void handler(int number, siginfo_t *info, void *context) {
  (void)context;
  if (number != SIGUSR1 || info->si_signo != SIGUSR1 ||
      info->si_code != SI_TIMER || (uintptr_t)info->si_value.sival_ptr != marker)
    invalid = 1;
  caught++;
}
static int arm(timer_t timer, long initial, long interval) {
  struct itimerspec value = {.it_value = {.tv_nsec = initial},
                            .it_interval = {.tv_nsec = interval}};
  return timer_settime(timer, 0, &value, NULL);
}
static int wait_for(const sigset_t *mask, siginfo_t *info) {
  const struct timespec limit = {.tv_sec = 2};
  return sigtimedwait(mask, info, &limit);
}

int main(void) {
  sigset_t selected;
  CHECK(sigemptyset(&selected) == 0);
  CHECK(sigaddset(&selected, SIGUSR1) == 0);
  CHECK(sigprocmask(SIG_BLOCK, &selected, NULL) == 0);
  struct sigevent event = {.sigev_notify = SIGEV_SIGNAL,
                          .sigev_signo = SIGUSR1,
                          .sigev_value.sival_ptr = (void *)marker};
  timer_t timer;
  CHECK(timer_create(CLOCK_MONOTONIC, &event, &timer) == 0);
  CHECK(arm(timer, 10000000, 10000000) == 0);
  struct timespec delay = {.tv_nsec = 80000000};
  while (nanosleep(&delay, &delay) != 0)
    CHECK(errno == EINTR);
  siginfo_t info;
  CHECK(wait_for(&selected, &info) == SIGUSR1);
  CHECK(info.si_code == SI_TIMER &&
        (uintptr_t)info.si_value.sival_ptr == marker);
  CHECK(timer_getoverrun(timer) > 0);
  CHECK(timer_delete(timer) == 0);
  const struct timespec zero = {0};
  errno = 0;
  CHECK(sigtimedwait(&selected, &info, &zero) == -1 && errno == EAGAIN);

  /* Equal-number notifications from independent timers must not coalesce. */
  timer_t pair[2];
  for (unsigned i = 0; i < 2; i++) {
    event.sigev_value.sival_ptr = (void *)(uintptr_t)(i + 1);
    CHECK(timer_create(CLOCK_MONOTONIC, &event, &pair[i]) == 0);
    CHECK(arm(pair[i], 10000000, 0) == 0);
  }
  unsigned seen = 0;
  for (unsigned i = 0; i < 2; i++) {
    CHECK(wait_for(&selected, &info) == SIGUSR1 && info.si_code == SI_TIMER);
    uintptr_t value = (uintptr_t)info.si_value.sival_ptr;
    CHECK(value == 1 || value == 2);
    CHECK(!(seen & (1u << value)));
    seen |= 1u << value;
  }
  CHECK(timer_delete(pair[0]) == 0 && timer_delete(pair[1]) == 0);

  struct sigaction action = {.sa_sigaction = handler, .sa_flags = SA_SIGINFO};
  CHECK(sigemptyset(&action.sa_mask) == 0);
  CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
  CHECK(sigprocmask(SIG_UNBLOCK, &selected, NULL) == 0);
  event.sigev_value.sival_ptr = (void *)marker;
  CHECK(timer_create(CLOCK_MONOTONIC, &event, &timer) == 0);
  CHECK(arm(timer, 20000000, 0) == 0);
  struct timespec end, now;
  CHECK(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
  end.tv_sec += 2;
  /* No blocking service RPC, read or explicit signal-drain call in this loop:
   * the real native interrupt/upcall must invoke the SA_SIGINFO handler. */
  do {
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    if (caught)
      break;
  } while (now.tv_sec < end.tv_sec ||
           (now.tv_sec == end.tv_sec && now.tv_nsec < end.tv_nsec));
  CHECK(caught == 1 && !invalid);
  CHECK(timer_getoverrun(timer) == 0);
  CHECK(timer_delete(timer) == 0);

  /* NULL sigevent defaults to SIGALRM and the returned timer ID as sigval. */
  CHECK(sigemptyset(&selected) == 0);
  CHECK(sigaddset(&selected, SIGALRM) == 0);
  CHECK(sigprocmask(SIG_BLOCK, &selected, NULL) == 0);
  CHECK(timer_create(CLOCK_MONOTONIC, NULL, &timer) == 0);
  CHECK(arm(timer, 10000000, 0) == 0);
  CHECK(wait_for(&selected, &info) == SIGALRM);
  CHECK(info.si_code == SI_TIMER &&
        (uintptr_t)info.si_value.sival_ptr == (uintptr_t)timer);
  CHECK(timer_delete(timer) == 0);
  puts("timer-signal: PASS");
  return 0;
}
