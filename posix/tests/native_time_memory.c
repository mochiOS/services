#define main clock_sleep_regressions
#include "native_clock_nanosleep.c"
#undef main
#include <setjmp.h>
#include <sys/mman.h>
#include <sys/times.h>

static unsigned operation;
static void *bad_input, *bad_output;
static sigjmp_buf fault_jump;
static int invalid_time(void) {
  if (operation == 0) return clock_gettime(CLOCK_MONOTONIC, bad_output);
  if (operation == 1) return clock_getres(CLOCK_MONOTONIC, bad_output);
  if (operation == 2) return times(bad_output) == (clock_t)-1 ? -1 : 0;
  if (operation == 3) return nanosleep(bad_input, NULL);
  errno = E2BIG;
  int result = clock_nanosleep(CLOCK_MONOTONIC, 0, bad_input, NULL);
  if (errno != E2BIG) _exit(92);
  return result == EFAULT ? -1 : 0;
}
static void memory_fault(int signal) {
  if (signal != SIGSEGV) _exit(91);
  if (invalid_time() != -1 || (operation < 4 && errno != EFAULT)) _exit(93);
  siglongjmp(fault_jump, 37);
}
int main(void) {
  sleeper = pthread_self();
  void *pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(pages != MAP_FAILED);
  bad_output = pages;
  bad_input = (char *)pages + 4096;
  CHECK(mprotect(bad_output, 4096, PROT_READ) == 0 &&
        mprotect(bad_input, 4096, PROT_NONE) == 0);
  struct sigaction fault_action = {0};
  fault_action.sa_handler = memory_fault;
  sigemptyset(&fault_action.sa_mask);
  CHECK(sigaction(SIGSEGV, &fault_action, NULL) == 0);
  for (operation = 0; operation < 5; ++operation) {
    CHECK(invalid_time() == -1 && (operation == 4 || errno == EFAULT));
    int jumped = sigsetjmp(fault_jump, 1);
    if (!jumped) {
      *(volatile char *)bad_input = 1;
      CHECK(0);
    }
    CHECK(jumped == 37);
  }
  struct sigaction signal_action = {0};
  signal_action.sa_handler = handler;
  sigemptyset(&signal_action.sa_mask);
  CHECK(sigaction(SIGUSR1, &signal_action, NULL) == 0);
  for (operation = 0; operation < 2; ++operation) {
    pthread_t thread;
    void *result;
    CHECK(pthread_create(&thread, NULL, sender, NULL) == 0);
    struct timespec request = {5, 0};
    errno = E2BIG;
    if (operation == 0)
      CHECK(nanosleep(&request, bad_output) == -1 && errno == EFAULT);
    else {
      int status = clock_nanosleep(CLOCK_MONOTONIC, 0, &request, bad_output);
      if (status != EFAULT || errno != E2BIG)
        fprintf(stderr, "time-memory: interrupted clock status=%d errno=%d caught=%d\n", status, errno, (int)caught);
      CHECK(status == EFAULT && errno == E2BIG);
    }
    CHECK(pthread_join(thread, &result) == 0 && result == NULL);
  }
  CHECK(munmap(pages, 8192) == 0);
  caught = 0;
  CHECK(clock_sleep_regressions() == 0);
  puts("time-memory: PASS five EFAULT APIs including active handlers, interrupted remainder copy, direct errno convention and clock-sleep regressions");
  return 0;
}
