/* Actual newlib -> POSIX -> filesystem canonical-path integration. */
#define main directory_baseline_main
#include "native_directory_io.c"
#undef main
#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/mman.h>

static sigjmp_buf destination;
static char expected[256];
static void fault_handler(int signal) {
  char nested[1024];
  if (signal != SIGSEGV || !realpath(".", nested) || strcmp(nested, expected))
    _exit(91);
  siglongjmp(destination, 37);
}
static int resolves(const char *input, const char *result) {
  char output[1025];
  memset(output, 0x5a, sizeof(output));
  CHECK(realpath(input, output) == output && strcmp(output, result) == 0);
  CHECK(output[strlen(result) + 1] == 0x5a);
  char *allocated = realpath(input, NULL);
  CHECK(allocated && strcmp(allocated, result) == 0);
  free(allocated);
  return 0;
}
int main(void) {
  char original[4097], base[256], child[300], output[1024];
  CHECK(getcwd(original, sizeof(original)) == original);
  snprintf(base, sizeof(base), "/tmp/canonical-%d", (int)getpid());
  snprintf(expected, sizeof(expected), "/tmp/canonical-moved-%d",
           (int)getpid());
  CHECK(mkdir(base, 0700) == 0 && chdir(base) == 0);
  CHECK(mkdir("inside", 0700) == 0);
  CHECK(symlink("inside", "link") == 0);
  CHECK(symlink("loop", "loop") == 0);
  int file = open("file", O_CREAT | O_WRONLY, 0000);
  CHECK(file >= 0 && close(file) == 0);
  CHECK(link("file", "alias") == 0);
  CHECK(rename(base, expected) == 0);
  snprintf(child, sizeof(child), "%s/inside", expected);
  CHECK(resolves("link/.", child) == 0);
  CHECK(resolves("link/..", expected) == 0);
  snprintf(child, sizeof(child), "%s/alias", expected);
  CHECK(resolves("alias", child) == 0);
  struct {
    const char *path;
    int error;
  } failures[] = {{"missing", ENOENT},
                  {"missing/../inside", ENOENT},
                  {"file/", ENOTDIR},
                  {"loop", ELOOP},
                  {"", ENOENT}};
  for (unsigned i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
    memset(output, 0x5a, sizeof(output));
    errno = 0;
    CHECK(realpath(failures[i].path, output) == NULL &&
          errno == failures[i].error);
    CHECK(output[0] == 0x5a);
  }
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
      (void)realpath(unreadable, output);
      CHECK(0);
    }
    CHECK(jumped == 37 && native_count() == baseline);
    jumped = sigsetjmp(destination, 1);
    if (!jumped) {
      (void)realpath(".", readonly);
      CHECK(0);
    }
    CHECK(jumped == 37 && native_count() == baseline);
    CHECK(resolves(".", expected) == 0);
  }
  CHECK(munmap(unreadable, 4096) == 0 && munmap(readonly, 4096) == 0);
  CHECK(unlink("file") == 0 && unlink("alias") == 0 && unlink("loop") == 0 &&
        unlink("link") == 0 && rmdir("inside") == 0);
  CHECK(rmdir(expected) == 0);
  errno = 0;
  CHECK(realpath(".", output) == NULL && errno == ENOENT);
  CHECK(chdir(original) == 0 && native_count() == baseline);
  puts("canonical-path: PASS symlinks, existence, rename, deleted cwd, "
       "allocation, 32 reentrant input/output faults and reference recovery");
  return 0;
}
