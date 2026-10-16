#define main directory_baseline_main
#include "native_directory_io.c"
#undef main
#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/mman.h>
static void *invalid, *readonly;
static int directory_fd;
static char full_link[256];
static sigjmp_buf jump_target;
static volatile sig_atomic_t caught;
static void handler(int signal) {
  char output[64];
  if (signal != SIGSEGV || openat(directory_fd, invalid, O_RDONLY) != -1 ||
      errno != EFAULT || readlinkat(directory_fd, "link", readonly, 16) != -1 ||
      errno != EFAULT || getcwd(readonly, 64) != NULL || errno != EFAULT ||
      realpath(full_link, readonly) != NULL || errno != EFAULT ||
      readlinkat(directory_fd, "link", output, sizeof(output)) != 4 ||
      memcmp(output, "dest", 4))
    _exit(91);
  caught = 1;
  siglongjmp(jump_target, 37);
}
int main(void) {
  char directory[128], output[1024];
  snprintf(directory, sizeof(directory), "/tmp/usercopy-%d", (int)getpid());
  snprintf(full_link, sizeof(full_link), "%s/link", directory);
  CHECK(mkdir(directory, 0700) == 0);
  directory_fd = open(directory, O_RDONLY | O_DIRECTORY);
  CHECK(directory_fd >= 0);
  int file = openat(directory_fd, "dest", O_CREAT | O_RDWR, 0600);
  CHECK(file >= 0 && close(file) == 0 &&
        symlinkat("dest", directory_fd, "link") == 0);
  invalid = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  readonly = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(invalid != MAP_FAILED && readonly != MAP_FAILED);
  CHECK(realpath(full_link, output) == output);
  struct sigaction action = {0};
  action.sa_handler = handler;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  int64_t baseline = native_count();
  for (unsigned round = 0; round < 16; ++round) {
    struct stat status;
    CHECK(openat(directory_fd, invalid, O_RDONLY) == -1 && errno == EFAULT);
    CHECK(truncate(invalid, 1) == -1 && errno == EFAULT);
    CHECK(stat(invalid, &status) == -1 && errno == EFAULT);
    CHECK(access(invalid, 0) == -1 && errno == EFAULT);
    CHECK(mkdir(invalid, 0700) == -1 && errno == EFAULT);
    CHECK(renameat(directory_fd, "dest", directory_fd, invalid) == -1 &&
          errno == EFAULT);
    CHECK(symlinkat("dest", directory_fd, invalid) == -1 && errno == EFAULT);
    CHECK(readlinkat(directory_fd, invalid, output, sizeof(output)) == -1 &&
          errno == EFAULT);
    CHECK(realpath(invalid, output) == NULL && errno == EFAULT);
    CHECK(readlinkat(directory_fd, "link", readonly, 16) == -1 &&
          errno == EFAULT);
    CHECK(realpath(full_link, readonly) == NULL && errno == EFAULT);
    CHECK(getcwd(readonly, 64) == NULL && errno == EFAULT);
    CHECK(native_count() == baseline);
    caught = 0;
    int jumped = sigsetjmp(jump_target, 1);
    if (!jumped) {
      (void)*(volatile char *)invalid;
      CHECK(0);
    }
    CHECK(jumped == 37 && caught && native_count() == baseline);
  }
  CHECK(munmap(invalid, 4096) == 0 && munmap(readonly, 4096) == 0);
  CHECK(unlinkat(directory_fd, "link", 0) == 0 &&
        unlinkat(directory_fd, "dest", 0) == 0);
  CHECK(close(directory_fd) == 0 && rmdir(directory) == 0);
  puts("posix-usercopy: PASS EFAULT pathname/copyout APIs, nested EFAULT "
       "inside 16 ordinary SIGSEGV handlers, stable Handle counts");
  return 0;
}
