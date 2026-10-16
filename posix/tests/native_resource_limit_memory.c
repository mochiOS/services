#define main resource_policy_regressions
#include "native_resource_policy.c"
#undef main
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>

static unsigned operation;
static unsigned char *pages;
static sigjmp_buf fault_jump;
static int invalid_limit(void) {
  struct rlimit *unreadable = (struct rlimit *)(pages + 4096);
  struct rlimit *input_boundary = (struct rlimit *)(pages + 4096 - 8);
  struct rlimit *readonly = (struct rlimit *)(pages + 12288);
  struct rlimit *output_boundary = (struct rlimit *)(pages + 12288 - 8);
  switch (operation) {
  case 0: return getrlimit(RLIMIT_NOFILE, unreadable);
  case 1: return getrlimit(RLIMIT_NOFILE, readonly);
  case 2: return setrlimit(RLIMIT_NOFILE, unreadable);
  case 3: return setrlimit(RLIMIT_NOFILE, input_boundary);
  case 4: return prlimit(0, RLIMIT_NOFILE, unreadable, NULL);
  case 5: return prlimit(0, RLIMIT_NOFILE, input_boundary, NULL);
  case 6: return prlimit(0, RLIMIT_NOFILE, NULL, unreadable);
  case 7: return prlimit(0, RLIMIT_NOFILE, NULL, readonly);
  default: return prlimit(0, RLIMIT_NOFILE, NULL, output_boundary);
  }
}
static void memory_fault(int signal) {
  if (signal != SIGSEGV || invalid_limit() != -1 || errno != EFAULT)
    _exit(91);
  siglongjmp(fault_jump, 37);
}
int main(void) {
  struct rlimit original, observed;
  CHECK(getrlimit(RLIMIT_NOFILE, &original) == 0);
  pages = mmap(NULL, 16384, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(pages != MAP_FAILED);
  memcpy(pages + 4096 - 8, &original.rlim_cur, 8);
  CHECK(mprotect(pages + 4096, 4096, PROT_NONE) == 0);
  CHECK(mprotect(pages + 12288, 4096, PROT_READ) == 0);
  struct sigaction action = {0};
  action.sa_handler = memory_fault;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  int64_t baseline = RP(680, 0, 0, 0, 0, 0);
  for (operation = 0; operation < 9; ++operation) {
    CHECK(invalid_limit() == -1 && errno == EFAULT);
    int jumped = sigsetjmp(fault_jump, 1);
    if (!jumped) {
      *(volatile char *)(pages + 4096) = 1;
      CHECK(0);
    }
    CHECK(jumped == 37);
    CHECK(getrlimit(RLIMIT_NOFILE, &observed) == 0);
    CHECK(observed.rlim_cur == original.rlim_cur &&
          observed.rlim_max == original.rlim_max);
    CHECK(RP(680, 0, 0, 0, 0, 0) == baseline);
  }
  CHECK(original.rlim_cur > 16);
  struct rlimit changed = original;
  changed.rlim_cur--;
  struct rlimit aliased = changed;
  CHECK(prlimit(0, RLIMIT_NOFILE, &aliased, &aliased) == 0);
  CHECK(aliased.rlim_cur == original.rlim_cur &&
        aliased.rlim_max == original.rlim_max);
  CHECK(getrlimit(RLIMIT_NOFILE, &observed) == 0 &&
        observed.rlim_cur == changed.rlim_cur);
  CHECK(setrlimit(RLIMIT_NOFILE, &original) == 0);
  CHECK(prlimit(0, RLIMIT_NOFILE, &changed,
                (struct rlimit *)(pages + 12288)) == -1 && errno == EFAULT);
  CHECK(getrlimit(RLIMIT_NOFILE, &observed) == 0 &&
        observed.rlim_cur == changed.rlim_cur);
  CHECK(setrlimit(RLIMIT_NOFILE, &original) == 0);
  CHECK(munmap(pages, 16384) == 0);
  CHECK(RP(680, 0, 0, 0, 0, 0) == baseline);
  CHECK(resource_policy_regressions() == 0);
  puts("resource-limit-memory: PASS 9 EFAULT cases including active handlers, "
       "cross-page copies, aliasing, late copyout failure and resource policy regressions");
  return 0;
}
