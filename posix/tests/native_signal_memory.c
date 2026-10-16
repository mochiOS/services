#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

static unsigned operation;
static void *unreadable, *readonly;
static sigset_t waited;
static sigjmp_buf jump;
static volatile sig_atomic_t delivered;
#define CHECK(test)                                                            \
  do {                                                                         \
    if (!(test)) {                                                             \
      fprintf(stderr, "signal-memory: FAIL op=%u line=%d errno=%d: %s\n",      \
              operation, __LINE__, errno, #test);                              \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static int64_t handles(void) {
  uint64_t number = 680;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(0), "S"(0), "d"(0)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
static int direct_error(void) {
  return operation == 4 || operation == 5 || operation == 7 || operation == 8;
}
static int invalid_signal_memory(void) {
  struct timespec zero = {0};
  if (operation == 8 || operation == 11 || operation == 12)
    if (raise(SIGUSR2))
      return 0;
  errno = direct_error() ? E2BIG : 0;
  switch (operation) {
  case 0:
    return sigaction(SIGUSR1, unreadable, NULL);
  case 1:
    return sigaction(SIGUSR1, NULL, readonly);
  case 2:
    return sigprocmask(SIG_BLOCK, unreadable, NULL);
  case 3:
    return sigprocmask(SIG_BLOCK, NULL, readonly);
  case 4:
    return pthread_sigmask(SIG_BLOCK, unreadable, NULL) == EFAULT ? -1 : 0;
  case 5:
    return pthread_sigmask(SIG_BLOCK, NULL, readonly) == EFAULT ? -1 : 0;
  case 6:
    return sigpending(readonly);
  case 7: {
    int selected;
    return sigwait(unreadable, &selected) == EFAULT ? -1 : 0;
  }
  case 8:
    return sigwait(&waited, readonly) == EFAULT ? -1 : 0;
  case 9:
    return sigwaitinfo(unreadable, NULL);
  case 10:
    return sigtimedwait(unreadable, NULL, &zero);
  case 11:
    return sigwaitinfo(&waited, readonly);
  case 12:
    return sigtimedwait(&waited, readonly, &zero);
  case 13:
    return sigemptyset(readonly);
  case 14:
    return sigfillset(readonly);
  case 15:
    return sigaddset(unreadable, SIGUSR1);
  case 16:
    return sigdelset(unreadable, SIGUSR1);
  case 17:
    return sigismember(unreadable, SIGUSR1);
  case 18:
    return sigaddset(readonly, SIGUSR1);
  default:
    return sigdelset(readonly, SIGUSR1);
  }
}
static int expected_error(void) {
  return errno == (direct_error() ? E2BIG : EFAULT);
}
static void fault(int signal) {
  if (signal != SIGSEGV || invalid_signal_memory() != -1 || !expected_error())
    _exit(93);
  siglongjmp(jump, 37);
}
static void caught(int signal) {
  if (signal == SIGUSR1)
    delivered++;
}
int main(void) {
  unsigned char *pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(pages != MAP_FAILED);
  unreadable = pages;
  readonly = pages + 4096;
  CHECK(mprotect(unreadable, 4096, PROT_NONE) == 0 &&
        mprotect(readonly, 4096, PROT_READ) == 0);
  CHECK(sigemptyset(&waited) == 0 && sigaddset(&waited, SIGUSR2) == 0);
  sigset_t original_mask;
  CHECK(pthread_sigmask(SIG_BLOCK, &waited, &original_mask) == 0);
  struct sigaction action = {0};
  action.sa_handler = fault;
  CHECK(sigemptyset(&action.sa_mask) == 0 &&
        sigaction(SIGSEGV, &action, NULL) == 0);
  int64_t baseline = handles();
  for (operation = 0; operation < 20; ++operation) {
    CHECK(invalid_signal_memory() == -1 && expected_error());
    int jumped = sigsetjmp(jump, 1);
    if (!jumped) {
      *(volatile char *)unreadable = 1;
      CHECK(0);
    }
    CHECK(jumped == 37);
    sigset_t pending;
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGUSR2) == 0);
    CHECK(handles() == baseline);
  }
  struct sigaction previous, ignored = {0}, queried;
  ignored.sa_handler = SIG_IGN;
  CHECK(sigemptyset(&ignored.sa_mask) == 0 &&
        sigaction(SIGUSR1, &ignored, &previous) == 0);
  action.sa_handler = caught;
  action.sa_flags = SA_RESTART;
  CHECK(sigaction(SIGUSR1, &action, readonly) == -1 && errno == EFAULT);
  CHECK(sigaction(SIGUSR1, NULL, &queried) == 0 &&
        queried.sa_handler == caught && queried.sa_flags == SA_RESTART);
  CHECK(raise(SIGUSR1) == 0 && delivered == 1);
  CHECK(sigaction(SIGUSR1, &ignored, NULL) == 0);
  struct sigaction alias = action;
  CHECK(sigaction(SIGUSR1, &alias, &alias) == 0 && alias.sa_handler == SIG_IGN);
  CHECK(sigaction(SIGUSR1, NULL, &queried) == 0 &&
        queried.sa_handler == caught);
  sigset_t unblock, mask_before;
  CHECK(sigemptyset(&unblock) == 0 && sigaddset(&unblock, SIGUSR1) == 0);
  CHECK(pthread_sigmask(SIG_SETMASK, NULL, &mask_before) == 0);
  for (unsigned api = 0; api < 2; ++api) {
    for (unsigned mode = 0; mode < 2; ++mode) {
      CHECK(pthread_sigmask(SIG_BLOCK, &unblock, NULL) == 0);
      sig_atomic_t before = delivered;
      CHECK(raise(SIGUSR1) == 0 && delivered == before);
      errno = E2BIG;
      const sigset_t *requested = mode ? &mask_before : &unblock;
      int how = mode ? SIG_SETMASK : SIG_UNBLOCK;
      if (api == 0)
        CHECK(sigprocmask(how, requested, readonly) == -1 && errno == EFAULT);
      else
        CHECK(pthread_sigmask(how, requested, readonly) == EFAULT &&
              errno == E2BIG);
      CHECK(delivered == before + 1);
      sigset_t pending, current;
      CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGUSR1) == 0);
      CHECK(pthread_sigmask(SIG_SETMASK, NULL, &current) == 0 &&
            current == mask_before);
    }
  }
  CHECK(sigaction(SIGUSR1, &previous, NULL) == 0);
  sigset_t mask_alias;
  CHECK(sigemptyset(&mask_alias) == 0 && sigaddset(&mask_alias, SIGUSR1) == 0);
  CHECK(pthread_sigmask(SIG_BLOCK, &mask_alias, &mask_alias) == 0 &&
        sigismember(&mask_alias, SIGUSR1) == 0);
  sigset_t observed;
  CHECK(pthread_sigmask(SIG_SETMASK, NULL, &observed) == 0 &&
        sigismember(&observed, SIGUSR1) == 1);
  CHECK(pthread_sigmask(SIG_SETMASK, &mask_alias, NULL) == 0);
  CHECK(raise(SIGUSR2) == 0);
  siginfo_t info;
  CHECK(sigwaitinfo(&waited, &info) == SIGUSR2 && info.si_signo == SIGUSR2 &&
        info.si_pid == getpid());
  CHECK(pthread_sigmask(SIG_SETMASK, &original_mask, NULL) == 0);
  CHECK(munmap(pages, 8192) == 0 && handles() == baseline);
  puts("signal-memory: PASS 20 EFAULT cases including active handlers, direct "
       "errno conventions, consumed wait notifications, committed disposition "
       "coherence, aliased inputs/outputs and 4 committed-unblock copy "
       "failures");
  return 0;
}
