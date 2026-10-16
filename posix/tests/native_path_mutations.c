/* Real single-path mutations preserve directory ownership across faults. */
#define main directory_baseline_main
#include "native_directory_io.c"
#undef main
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>

static char parent[96];
static int source, replacement;
static volatile sig_atomic_t faulted;
static sigjmp_buf destination;
static void failed_path(int signal) {
  if (signal != SIGSEGV || close(source))
    _exit(91);
  replacement = open(parent, O_RDONLY | O_DIRECTORY);
  if (replacement != source)
    _exit(92);
  faulted = 1;
  siglongjmp(destination, 37);
}
static int mutate(unsigned operation, const char *path) {
  switch (operation) {
  case 0:
    return fchmodat(source, path, 0640, 0);
  case 1:
    return fchownat(source, path, (uid_t)-1, (gid_t)-1, 0);
  case 2:
    return unlinkat(source, path, 0);
  default:
    return mkdirat(source, path, 0750);
  }
}
int main(void) {
  snprintf(parent, sizeof(parent), "/tmp/path-mutations-%d", (int)getpid());
  CHECK(mkdir(parent, 0700) == 0);
  struct sigaction action = {0};
  action.sa_handler = failed_path;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  /* Resolve the normal file and metadata endpoints before measuring. */
  source = open(parent, O_RDONLY | O_DIRECTORY);
  CHECK(source >= 0);
  struct stat status;
  CHECK(fstat(source, &status) == 0 && close(source) == 0);
  int64_t baseline = native_count();
  for (unsigned round = 0; round < 4; ++round) {
    for (unsigned operation = 0; operation < 4; ++operation) {
      for (unsigned fault = 0; fault < 2; ++fault) {
        source = open(parent, O_RDONLY | O_DIRECTORY);
        CHECK(source >= 0);
        if (operation != 3) {
          int file = openat(source, "target", O_CREAT | O_EXCL | O_RDWR, 0600);
          CHECK(file >= 0 && close(file) == 0);
        }
        void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(page != MAP_FAILED);
        strcpy(page, "target");
        if (fault)
          CHECK(mprotect(page, 4096, PROT_NONE) == 0);
        replacement = -1;
        faulted = 0;
        int jumped = sigsetjmp(destination, 1);
        if (!jumped) {
          CHECK(mutate(operation, page) == 0 && !fault);
          if (operation == 2) {
            errno = 0;
            CHECK(fstatat(source, "target", &status, 0) == -1 &&
                  errno == ENOENT);
          } else {
            CHECK(fstatat(source, "target", &status, 0) == 0);
            if (operation == 0)
              CHECK((status.st_mode & 0777) == 0640);
            if (operation == 3)
              CHECK(S_ISDIR(status.st_mode) && (status.st_mode & 0777) == 0750);
          }
        } else {
          CHECK(jumped == 37 && fault && faulted);
          CHECK(replacement == source && native_count() == baseline + 1);
          CHECK(fstat(source, &status) == 0 && S_ISDIR(status.st_mode));
        }
        if (fault || operation != 2) {
          if (operation != 3 || !fault)
            CHECK(unlinkat(source, "target",
                           operation == 3 ? AT_REMOVEDIR : 0) == 0);
        }
        CHECK(close(source) == 0 && munmap(page, 4096) == 0);
        CHECK(native_count() == baseline);
      }
    }
  }
  CHECK(rmdir(parent) == 0 && native_count() == baseline);
  puts("path-mutations: PASS 32 chmod/chown/unlink/mkdir cases, input faults, "
       "FD reuse and reference recovery");
  return 0;
}
