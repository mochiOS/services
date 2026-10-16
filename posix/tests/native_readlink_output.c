/* Readlink's real newlib copyout boundary, including nonlocal signal exits. */
#define main directory_baseline_main
#include "native_directory_io.c"
#undef main
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>

static sigjmp_buf destination;
static int directory_fd;
static const char link_name[] = "link-\xff";
static const char target[] = "destination-\xfe";
static void fault_handler(int signal) {
  char nested[64];
  if (signal != SIGSEGV ||
      readlinkat(directory_fd, link_name, nested, sizeof(nested)) !=
          (ssize_t)strlen(target) ||
      memcmp(nested, target, strlen(target)))
    _exit(91);
  siglongjmp(destination, 37);
}
int main(void) {
  char directory[128], output[64];
  snprintf(directory, sizeof(directory), "/tmp/readlink-copy-%d",
           (int)getpid());
  CHECK(mkdir(directory, 0700) == 0);
  directory_fd = open(directory, O_RDONLY | O_DIRECTORY);
  CHECK(directory_fd >= 0 && symlinkat(target, directory_fd, link_name) == 0);
  for (size_t size = 1; size < strlen(target) + 3; ++size) {
    memset(output, 0x5a, sizeof(output));
    size_t expected = size < strlen(target) ? size : strlen(target);
    CHECK(readlinkat(directory_fd, link_name, output, size) ==
          (ssize_t)expected);
    CHECK(memcmp(output, target, expected) == 0 && output[expected] == 0x5a);
  }
  memset(output, 0x5a, sizeof(output));
  CHECK(readlinkat(directory_fd, link_name, output, INTPTR_MAX) ==
        (ssize_t)strlen(target));
  CHECK(output[strlen(target)] == 0x5a);
  errno = 0;
  CHECK(readlinkat(directory_fd, "missing", output, sizeof(output)) == -1 &&
        errno == ENOENT);
  struct sigaction action = {0};
  action.sa_handler = fault_handler;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  void *unreadable =
      mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  void *readonly =
      mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(unreadable != MAP_FAILED && readonly != MAP_FAILED);
  int64_t baseline = native_count();
  for (unsigned round = 0; round < 16; ++round) {
    int jumped = sigsetjmp(destination, 1);
    if (!jumped) {
      (void)readlinkat(directory_fd, unreadable, output, sizeof(output));
      CHECK(0);
    }
    CHECK(jumped == 37 && native_count() == baseline);
    jumped = sigsetjmp(destination, 1);
    if (!jumped) {
      (void)readlinkat(directory_fd, link_name, readonly, 4096);
      CHECK(0);
    }
    CHECK(jumped == 37 && native_count() == baseline);
    CHECK(readlinkat(directory_fd, link_name, output, sizeof(output)) ==
          (ssize_t)strlen(target));
  }
  CHECK(munmap(unreadable, 4096) == 0 && munmap(readonly, 4096) == 0);
  CHECK(unlinkat(directory_fd, link_name, 0) == 0 && close(directory_fd) == 0 &&
        rmdir(directory) == 0);
  puts("readlink-output: PASS raw targets, prefix/no NUL, large capacity, "
       "32 nested input/copyout faults and stable "
       "Handle counts");
  return 0;
}
