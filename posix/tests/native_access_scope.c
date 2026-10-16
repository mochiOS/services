/* C access APIs use authenticated POSIX policy, not a local stat shortcut. */
#define main directory_baseline_main
#include "native_directory_io.c"
#undef main
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>

static char parent[96];
static int directory;
static sigjmp_buf destination;
static volatile sig_atomic_t faulted;
static void failed_path(int signal) {
  if (signal != SIGSEGV || close(directory))
    _exit(91);
  if (open(parent, O_RDONLY | O_DIRECTORY) != directory)
    _exit(92);
  faulted = 1;
  siglongjmp(destination, 37);
}
int main(void) {
  char absolute[128], moved[96];
  snprintf(parent, sizeof(parent), "/tmp/access-scope-%d", (int)getpid());
  snprintf(moved, sizeof(moved), "/tmp/access-scope-moved-%d", (int)getpid());
  CHECK(mkdir(parent, 0755) == 0);
  directory = open(parent, O_RDONLY | O_DIRECTORY);
  CHECK(directory >= 0);
  int file = openat(directory, "entry", O_CREAT | O_EXCL | O_RDWR, 0600);
  CHECK(file >= 0 && close(file) == 0);
  CHECK(symlinkat("missing", directory, "broken") == 0);
  for (int modes = 0; modes < 8; ++modes) {
    errno = 0;
    int result = faccessat(directory, "entry", modes, 0);
    CHECK(modes & X_OK ? result == -1 && errno == EACCES : result == 0);
  }
  CHECK(faccessat(directory, "broken", F_OK, AT_SYMLINK_NOFOLLOW) == 0);
  errno = 0;
  CHECK(faccessat(directory, "broken", F_OK, 0) == -1 && errno == ENOENT);
  CHECK(rename(parent, moved) == 0);
  strcpy(parent, moved);
  snprintf(absolute, sizeof(absolute), "%s/entry", parent);
  CHECK(access(absolute, R_OK | W_OK) == 0);
  CHECK(eaccess(absolute, R_OK) == 0 && euidaccess(absolute, R_OK) == 0);
  CHECK(faccessat(-123, absolute, R_OK, AT_EACCESS) == 0);
  CHECK(faccessat(directory, "entry", R_OK, AT_EACCESS) == 0);
  for (int invalid = -1; invalid <= 8; invalid += 9) {
    errno = 0;
    CHECK(faccessat(directory, "entry", invalid, 0) == -1 && errno == EINVAL);
  }
  errno = 0;
  CHECK(faccessat(directory, "entry", F_OK, 4) == -1 && errno == EINVAL);
  errno = 0;
  CHECK(faccessat(-123, "entry", F_OK, 0) == -1 && errno == EBADF);
  pid_t child = fork();
  CHECK(child >= 0);
  if (!child) {
    if (geteuid() == 0) {
      if (setreuid(501, 0))
        _exit(93);
      errno = 0;
      if (access(absolute, R_OK) != -1 || errno != EACCES)
        _exit(94);
      if (eaccess(absolute, R_OK) || euidaccess(absolute, R_OK))
        _exit(95);
      errno = 0;
      if (faccessat(directory, "entry", R_OK, 0) != -1 || errno != EACCES)
        _exit(96);
      if (faccessat(directory, "entry", R_OK, AT_EACCESS))
        _exit(97);
      puts("access-scope: distinct real/effective IDs PASS");
    }
    _exit(0);
  }
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  int64_t baseline = native_count();
  struct sigaction action = {0};
  action.sa_handler = failed_path;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  void *page = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(page != MAP_FAILED);
  for (unsigned round = 0; round < 8; ++round) {
    for (unsigned operation = 0; operation < 2; ++operation) {
      faulted = 0;
      int jumped = sigsetjmp(destination, 1);
      if (!jumped) {
        if (operation)
          faccessat(directory, page, F_OK, 0);
        else
          access(page, F_OK);
        CHECK(0);
      } else {
        CHECK(jumped == 37 && faulted && native_count() == baseline);
        CHECK(faccessat(directory, "entry", R_OK, 0) == 0);
      }
    }
  }
  CHECK(munmap(page, 4096) == 0);
  CHECK(unlinkat(directory, "entry", 0) == 0 &&
        unlinkat(directory, "broken", 0) == 0);
  CHECK(close(directory) == 0 && rmdir(parent) == 0 &&
        native_count() == baseline - 1);
  puts("access-scope: PASS modes, nofollow, retained directory, errors, 16 "
       "input faults and reference recovery");
  return 0;
}
