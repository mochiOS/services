/* Directory policy remains in userspace, with owned path/FD operations. */
#define main directory_baseline_main
#include "native_directory_io.c"
#undef main
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>

extern int spawn_regression_main(int, char **);
static sigjmp_buf destination;
static char parent[96];
static int directory;
static volatile sig_atomic_t faulted;
static void failed_path(int signal) {
  if (signal != SIGSEGV || close(directory))
    _exit(91);
  if (open(parent, O_RDONLY | O_DIRECTORY) != directory)
    _exit(92);
  faulted = 1;
  siglongjmp(destination, 37);
}
int main(int argc, char **argv) {
  if (argc == 2 && !strcmp(argv[1], "--verify"))
    return spawn_regression_main(argc, argv);
  char original[4096], current[4096], moved[96], nested[128];
  CHECK(getcwd(original, sizeof(original)) != NULL);
  int initial = open(original, O_RDONLY | O_DIRECTORY);
  CHECK(initial >= 0);
  snprintf(parent, sizeof(parent), "/tmp/directory-policy-%d", (int)getpid());
  snprintf(moved, sizeof(moved), "/tmp/directory-policy-moved-%d",
           (int)getpid());
  snprintf(nested, sizeof(nested), "%s/nested", parent);
  CHECK(mkdir(parent, 0700) == 0 && mkdir(nested, 0700) == 0);
  directory = open(parent, O_RDONLY | O_DIRECTORY);
  CHECK(directory >= 0);
  CHECK(chdir(parent) == 0 && getcwd(current, sizeof(current)) != NULL);
  CHECK(!strcmp(parent, current));
  CHECK(rename(parent, moved) == 0);
  strcpy(parent, moved);
  CHECK(fchdir(directory) == 0 && getcwd(current, sizeof(current)) != NULL);
  CHECK(!strcmp(parent, current));
  for (unsigned round = 0; round < 8; ++round) {
    CHECK(chdir("nested") == 0 && fchdir(directory) == 0);
    errno = 0;
    CHECK(chdir("missing") == -1 && errno == ENOENT);
    CHECK(getcwd(current, sizeof(current)) && !strcmp(parent, current));
  }
  CHECK(fchdir(initial) == 0);
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
          chroot(page);
        else
          chdir(page);
        CHECK(0);
      } else {
        CHECK(jumped == 37 && faulted && native_count() == baseline);
        CHECK(getcwd(current, sizeof(current)) && !strcmp(original, current));
      }
    }
  }
  CHECK(munmap(page, 4096) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (!child) {
    if (geteuid() != 0) {
      errno = 0;
      _exit(chroot(parent) == -1 && errno == EPERM ? 0 : 93);
    }
    if (chroot(parent) || chdir("/") || chdir("..") ||
        !getcwd(current, sizeof(current)) || strcmp(current, "/"))
      _exit(94);
    _exit(0);
  }
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  CHECK(getcwd(current, sizeof(current)) && !strcmp(original, current));
  CHECK(close(directory) == 0 && close(initial) == 0);
  snprintf(nested, sizeof(nested), "%s/nested", parent);
  CHECK(rmdir(nested) == 0 && rmdir(parent) == 0);
  CHECK(native_count() == baseline - 2);
  puts("directory-policy: PASS cwd/rename, retained fchdir, 16 input faults "
       "and child root policy");
  return spawn_regression_main(argc, argv);
}
