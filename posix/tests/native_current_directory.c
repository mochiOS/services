/* Native newlib getcwd boundary: live cwd identity and output-copy faults. */
#define main directory_baseline_main
#include "native_directory_io.c"
#undef main
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>

static sigjmp_buf destination;
static volatile sig_atomic_t faulted;
static char expected[128];
static void failed_copy(int signal) {
  if (signal != SIGSEGV)
    _exit(91);
  char nested[256];
  if (!getcwd(nested, sizeof(nested)) || strcmp(nested, expected))
    _exit(92);
  faulted = 1;
  siglongjmp(destination, 37);
}
int main(void) {
  char original[4097], directory[128], output[256];
  CHECK(getcwd(original, sizeof(original)) == original);
  snprintf(directory, sizeof(directory), "/tmp/cwd-copy-%d", (int)getpid());
  snprintf(expected, sizeof(expected), "/tmp/cwd-moved-%d", (int)getpid());
  CHECK(mkdir(directory, 0700) == 0 && chdir(directory) == 0);
  CHECK(rename(directory, expected) == 0);
  CHECK(getcwd(output, sizeof(output)) == output &&
        strcmp(output, expected) == 0);
  memset(output, 0x5a, sizeof(output));
  CHECK(getcwd(output, strlen(expected) + 1) == output &&
        strcmp(output, expected) == 0 && output[strlen(expected) + 1] == 0x5a);
  for (unsigned capacity = 1; capacity <= strlen(expected); ++capacity) {
    memset(output, 0x5a, sizeof(output));
    errno = 0;
    CHECK(getcwd(output, capacity) == NULL && errno == ERANGE);
    for (unsigned index = 0; index < sizeof(output); ++index)
      CHECK(output[index] == 0x5a);
  }
  struct sigaction action = {0};
  action.sa_handler = failed_copy;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  void *readonly =
      mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(readonly != MAP_FAILED);
  int64_t baseline = native_count();
  for (unsigned round = 0; round < 16; ++round) {
    CHECK(getcwd(readonly, 4096) == NULL && errno == EFAULT);
    faulted = 0;
    int jumped = sigsetjmp(destination, 1);
    if (!jumped) {
      *(volatile char *)readonly = 1;
      CHECK(0);
    } else {
      CHECK(jumped == 37 && faulted);
    }
    CHECK(native_count() == baseline);
    CHECK(getcwd(output, sizeof(output)) == output &&
          strcmp(output, expected) == 0);
  }
  CHECK(munmap(readonly, 4096) == 0);
  int retained = open(".", O_RDONLY | O_DIRECTORY);
  CHECK(retained >= 0);
  struct stat before, after;
  CHECK(fstat(retained, &before) == 0 && rmdir(expected) == 0);
  CHECK(fstat(retained, &after) == 0 && after.st_ino == before.st_ino &&
        after.st_nlink == 0);
  memset(output, 0x5a, sizeof(output));
  errno = 0;
  CHECK(getcwd(output, sizeof(output)) == NULL && errno == ENOENT);
  CHECK(output[0] == 0x5a);
  errno = 0;
  CHECK(openat(retained, "resurrect", O_CREAT | O_RDWR, 0600) == -1 &&
        errno == ENOENT);
  int parent = openat(retained, "..", O_RDONLY | O_DIRECTORY);
  CHECK(parent >= 0 && fchdir(parent) == 0);
  CHECK(getcwd(output, sizeof(output)) == output &&
        strcmp(output, "/tmp") == 0);
  CHECK(fchdir(retained) == 0);
  errno = 0;
  CHECK(getcwd(output, sizeof(output)) == NULL && errno == ENOENT);
  CHECK(chdir(original) == 0 && close(parent) == 0 && close(retained) == 0);
  CHECK(native_count() == baseline);
  puts("current-directory: PASS exact/short buffers, live rename, retained "
       "deleted cwd and parent identity, "
       "EFAULT copyout, 16 ordinary memory faults and reference recovery");
  return 0;
}
