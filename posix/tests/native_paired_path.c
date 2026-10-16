/* A fault in the second input retires the first retained directory too. */
#define main directory_baseline_main
#include "native_directory_io.c"
#undef main
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>

static char parent[96], old_parent[112], new_parent[112];
static int old_fd, new_fd;
static volatile sig_atomic_t faulted;
static sigjmp_buf destination;
static void failed_path(int signal) {
  if (signal != SIGSEGV || close(old_fd) || close(new_fd))
    _exit(91);
  int first = open(old_parent, O_RDONLY | O_DIRECTORY);
  int second = open(new_parent, O_RDONLY | O_DIRECTORY);
  if (first != old_fd || second != new_fd)
    _exit(92);
  faulted = 1;
  siglongjmp(destination, 37);
}
static int operate(unsigned operation, const char *old, const char *next) {
  switch (operation) {
  case 0:
    return renameat(old_fd, old, new_fd, next);
  case 1:
    return linkat(old_fd, old, new_fd, next, 0);
  default:
    return symlinkat(old, new_fd, next);
  }
}
int main(void) {
  snprintf(parent, sizeof(parent), "/tmp/paired-path-%d", (int)getpid());
  snprintf(old_parent, sizeof(old_parent), "%s/old", parent);
  snprintf(new_parent, sizeof(new_parent), "%s/new", parent);
  CHECK(mkdir(parent, 0700) == 0);
  CHECK(mkdir(old_parent, 0700) == 0 && mkdir(new_parent, 0700) == 0);
  struct sigaction action = {0};
  action.sa_handler = failed_path;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  old_fd = open(old_parent, O_RDONLY | O_DIRECTORY);
  CHECK(old_fd >= 0);
  struct stat status;
  CHECK(fstat(old_fd, &status) == 0 && close(old_fd) == 0);
  int64_t baseline = native_count();
  for (unsigned round = 0; round < 4; ++round) {
    for (unsigned operation = 0; operation < 3; ++operation) {
      for (unsigned fault = 0; fault < 3; ++fault) {
        old_fd = open(old_parent, O_RDONLY | O_DIRECTORY);
        new_fd = open(new_parent, O_RDONLY | O_DIRECTORY);
        CHECK(old_fd >= 0 && new_fd >= 0);
        if (operation != 2) {
          int file = openat(old_fd, "source", O_CREAT | O_EXCL | O_RDWR, 0600);
          CHECK(file >= 0 && close(file) == 0);
        }
        void *page =
            mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(page != MAP_FAILED);
        faulted = 0;
        int jumped = sigsetjmp(destination, 1);
        if (!jumped) {
          const char *old = fault == 1       ? page
                            : operation == 2 ? "../old/source"
                                             : "source";
          const char *next = fault == 2 ? page : "result";
          CHECK(operate(operation, old, next) == 0 && fault == 0);
          CHECK(fstatat(new_fd, "result", &status, AT_SYMLINK_NOFOLLOW) == 0);
          if (operation == 2) {
            CHECK(S_ISLNK(status.st_mode));
            char target[64] = {0};
            CHECK(readlinkat(new_fd, "result", target, sizeof(target)) == 13);
            CHECK(!memcmp(target, "../old/source", 13));
          } else {
            CHECK(S_ISREG(status.st_mode));
            if (operation == 1) {
              struct stat original;
              CHECK(fstatat(old_fd, "source", &original, 0) == 0);
              CHECK(original.st_ino == status.st_ino && status.st_nlink == 2);
            }
          }
          CHECK(unlinkat(new_fd, "result", 0) == 0);
        } else {
          CHECK(jumped == 37 && fault && faulted);
          CHECK(native_count() == baseline + 2);
          CHECK(fstat(old_fd, &status) == 0 && S_ISDIR(status.st_mode));
          CHECK(fstat(new_fd, &status) == 0 && S_ISDIR(status.st_mode));
          errno = 0;
          CHECK(fstatat(new_fd, "result", &status, 0) == -1 && errno == ENOENT);
        }
        if (operation != 2 && (fault || operation == 1))
          CHECK(unlinkat(old_fd, "source", 0) == 0);
        CHECK(close(old_fd) == 0 && close(new_fd) == 0);
        CHECK(munmap(page, 4096) == 0 && native_count() == baseline);
      }
    }
  }
  CHECK(rmdir(old_parent) == 0 && rmdir(new_parent) == 0 && rmdir(parent) == 0);
  CHECK(native_count() == baseline);
  puts("paired-path: PASS 36 rename/link/symlink cases, first/second input "
       "faults, FD reuse and reference recovery");
  return 0;
}
