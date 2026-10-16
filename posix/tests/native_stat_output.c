#define main fcntl_baseline_main
#include "native_fcntl_status.c"
#undef main
#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <sys/stat.h>
_Static_assert(sizeof(struct stat) == 104, "newlib stat size");
_Static_assert(offsetof(struct stat, st_size) == 16, "newlib size offset");
_Static_assert(offsetof(struct stat, st_atim) == 24, "newlib time offset");
_Static_assert(offsetof(struct stat, st_blocks) == 80, "newlib block offset");
static sigjmp_buf jump_target;
static int current_fd;
static struct stat *readonly;
static void handler(int signal) {
  struct stat output;
  if (signal != SIGSEGV || fstat(current_fd, readonly) != -1 ||
      errno != EFAULT || fstat(current_fd, &output))
    _exit(91);
  siglongjmp(jump_target, 37);
}
int main(void) {
  snprintf(path, sizeof(path), "/tmp/stat-copy-%d", (int)getpid());
  snprintf(shared_name, sizeof(shared_name), "/stat-copy-%d", (int)getpid());
  readonly = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(readonly != MAP_FAILED);
  struct sigaction action = {0};
  action.sa_handler = handler;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  for (kind = 0; kind < 9; ++kind) {
    current_fd = create();
    CHECK(current_fd >= 0);
    struct {
      uint64_t before;
      struct stat value;
      uint64_t after;
    } output;
    output.before = output.after = UINT64_C(0xa5a5a5a5a5a5a5a5);
    CHECK(fstat(current_fd, &output.value) == 0);
    CHECK(output.before == output.after &&
          output.after == UINT64_C(0xa5a5a5a5a5a5a5a5));
    CHECK(output.value.st_spare4[0] == 0 && output.value.st_spare4[1] == 0);
    if (kind == 8) {
      struct stat by_path;
      CHECK(stat("/dev/null", &by_path) == 0);
      CHECK(S_ISCHR(output.value.st_mode) && output.value.st_rdev == 259);
      CHECK(by_path.st_dev == output.value.st_dev &&
            by_path.st_ino == output.value.st_ino &&
            by_path.st_rdev == output.value.st_rdev);
    }
    if (!kind) {
      CHECK(write(current_fd, "abc", 3) == 3 &&
            stat(path, &output.value) == 0 && output.value.st_size == 3);
      CHECK(stat(path, readonly) == -1 && errno == EFAULT);
      CHECK(lstat(path, readonly) == -1 && errno == EFAULT);
      CHECK(fstatat(-2, path, readonly, 0) == -1 && errno == EFAULT);
    }
    int64_t baseline = native_count();
    for (volatile unsigned round = 0; round < 16; ++round) {
      CHECK(fstat(current_fd, readonly) == -1 && errno == EFAULT);
      CHECK(fstat(current_fd, (void *)1) == -1 && errno == EFAULT);
      int jumped = sigsetjmp(jump_target, 1);
      if (!jumped) {
        *(volatile char *)readonly = 1;
        CHECK(0);
      }
      CHECK(jumped == 37 && native_count() == baseline);
    }
    CHECK(close(current_fd) == 0);
    if (auxiliary >= 0)
      CHECK(close(auxiliary) == 0);
  }
  struct stat system;
  int system_fd = open("/system", O_RDONLY | O_DIRECTORY);
  CHECK(system_fd >= 0 && fstat(system_fd, &system) == 0);
  struct stat system_path;
  CHECK(stat("/system", &system_path) == 0 &&
        system.st_dev == system_path.st_dev &&
        system.st_ino == system_path.st_ino && S_ISDIR(system.st_mode));
  CHECK(close(system_fd) == 0);
  CHECK(unlink(path) == 0 && munmap(readonly, 4096) == 0);
  puts("stat-output: PASS C ABI fields, EFAULT stat/lstat/fstatat and 9 FD "
       "kinds, 144 ordinary handlers with nested EFAULT and stable references");
  return 0;
}
