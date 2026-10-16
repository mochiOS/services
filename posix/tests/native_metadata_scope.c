/* Reuse metadata behavior coverage; the fixture does not depend on SDK
 * mkdtemp, which is still a stub in the separately maintained local SDK. */
#define mkdtemp fixture_directory
#define main metadata_regression_main
#include "native_fstatat.c"
#undef main
#undef mkdtemp
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <sys/mman.h>

char *fixture_directory(char *path) {
  char *suffix = strstr(path, "XXXXXX");
  if (!suffix)
    return NULL;
  snprintf(suffix, 7, "%06u", (unsigned)getpid() % 1000000);
  return mkdir(path, 0700) == 0 ? path : NULL;
}
static char parent[96];
static int source;
static sigjmp_buf destination;
static volatile sig_atomic_t faulted;
static int64_t native_count(void) {
  uint64_t number = 680;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"((uint64_t)0), "S"((uint64_t)0), "d"((uint64_t)0)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
static void failed_copy(int signal) {
  if (signal != SIGSEGV || close(source))
    _exit(91);
  if (open(parent, O_RDONLY | O_DIRECTORY) != source)
    _exit(92);
  faulted = 1;
  siglongjmp(destination, 37);
}
int main(void) {
  CHECK(metadata_regression_main() == 0);
  snprintf(parent, sizeof(parent), "/tmp/metadata-scope-%d", (int)getpid());
  CHECK(mkdir(parent, 0700) == 0);
  source = open(parent, O_RDONLY | O_DIRECTORY);
  CHECK(source >= 0);
  int file = openat(source, "entry", O_CREAT | O_EXCL | O_RDWR, 0600);
  CHECK(file >= 0 && write(file, "data", 4) == 4 && close(file) == 0);
  struct stat status;
  CHECK(fstatat(source, "entry", &status, 0) == 0 && close(source) == 0);
  struct sigaction action = {0};
  action.sa_handler = failed_copy;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  int64_t baseline = native_count();
  for (unsigned round = 0; round < 8; ++round) {
    for (unsigned fault = 0; fault < 3; ++fault) {
      source = open(parent, O_RDONLY | O_DIRECTORY);
      CHECK(source >= 0);
      void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      CHECK(page != MAP_FAILED);
      if (fault)
        CHECK(mprotect(page, 4096, fault == 1 ? PROT_NONE : PROT_READ) == 0);
      faulted = 0;
      int jumped = sigsetjmp(destination, 1);
      if (!jumped) {
        const char *path = fault == 1 ? page : "entry";
        struct stat *output = fault == 2 ? page : &status;
        CHECK(fstatat(source, path, output, 0) == 0 && fault == 0);
        CHECK(status.st_size == 4);
      } else {
        CHECK(jumped == 37 && fault && faulted &&
              native_count() == baseline + 1);
        CHECK(fstatat(source, "entry", &status, 0) == 0 && status.st_size == 4);
      }
      CHECK(close(source) == 0 && munmap(page, 4096) == 0);
      CHECK(native_count() == baseline);
    }
  }
  source = open(parent, O_RDONLY | O_DIRECTORY);
  CHECK(source >= 0 && unlinkat(source, "entry", 0) == 0 && close(source) == 0);
  CHECK(rmdir(parent) == 0 && native_count() == baseline);
  puts("metadata-scope: PASS 24 input/copyout/normal cases, FD reuse and "
       "reference recovery");
  return 0;
}
