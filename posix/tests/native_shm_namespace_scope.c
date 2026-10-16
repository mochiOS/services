/* Retain the full shared-memory fork/exec test before exercising namespace
 * errors, input faults and FD reservation reuse against the actual runtime. */
#define main shared_memory_regression_main
#include "native_posix_shared_memory.c"
#undef main
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>

static sigjmp_buf destination;
static volatile sig_atomic_t faulted;
static void failed_input(int signal) {
  if (signal != SIGSEGV)
    _exit(91);
  faulted = 1;
  siglongjmp(destination, 37);
}
static int64_t native_count(void) {
  uint64_t number = 680;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"((uint64_t)0), "S"((uint64_t)0), "d"((uint64_t)0)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
int main(int argc, char **argv) {
  if (argc == 5)
    return shared_memory_regression_main(argc, argv);
  CHECK(shared_memory_regression_main(argc, argv) == 0);
  const char *name = "/shm-namespace-scope";
  int source = shm_open(name, O_CREAT | O_EXCL | O_RDWR, 0600);
  CHECK(source >= 0 && ftruncate(source, 4096) == 0);
  int expected = shm_open(name, O_RDONLY, 0);
  CHECK(expected >= 0 && close(expected) == 0);
  void *bad = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(bad != MAP_FAILED);
  struct sigaction action = {0};
  action.sa_handler = failed_input;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  int64_t baseline = native_count();
  for (unsigned round = 0; round < 16; ++round) {
    errno = 0;
    CHECK(shm_open(name, O_CREAT | O_EXCL | O_RDWR, 0600) == -1 &&
          errno == EEXIST);
    errno = 0;
    CHECK(shm_open("/shm-namespace-missing", O_RDONLY, 0) == -1 &&
          errno == ENOENT);
    errno = 0;
    CHECK(shm_unlink("/shm-namespace-missing") == -1 && errno == ENOENT);
    for (volatile unsigned operation = 0; operation < 2; ++operation) {
      faulted = 0;
      int jumped = sigsetjmp(destination, 1);
      if (!jumped) {
        if (operation == 0)
          (void)shm_open(bad, O_RDONLY, 0);
        else
          (void)shm_unlink(bad);
        CHECK(0);
      } else {
        CHECK(jumped == 37 && faulted);
      }
      int reader = shm_open(name, O_RDONLY, 0);
      CHECK(reader == expected && native_count() == baseline + 1);
      CHECK(fcntl(reader, F_GETFD, 0) == FD_CLOEXEC && close(reader) == 0);
      CHECK(native_count() == baseline);
    }
  }
  CHECK(munmap(bad, 4096) == 0 && shm_unlink(name) == 0 && close(source) == 0);
  CHECK(native_count() == baseline - 1);
  puts("shm-namespace-scope: PASS 32 input faults, failed-open/unlink cleanup, "
       "CLOEXEC and repeated FD reservation reuse");
  return 0;
}
