/* Recover the real path scope after input/output faults and FD reuse. */
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
static const char target[] = "../destination/with-a-long-name";

static void failed_copy(int signal) {
  if (signal != SIGSEGV || close(source))
    _exit(91);
  replacement = open(parent, O_RDONLY | O_DIRECTORY);
  if (replacement != source)
    _exit(92);
  faulted = 1;
  siglongjmp(destination, 37);
}

int main(void) {
  snprintf(parent, sizeof(parent), "/tmp/path-io-%d", (int)getpid());
  CHECK(mkdir(parent, 0700) == 0);
  source = open(parent, O_RDONLY | O_DIRECTORY);
  CHECK(source >= 0 && symlinkat(target, source, "link") == 0);
  char output[128];
  CHECK(readlinkat(source, "link", output, sizeof(output)) ==
        (ssize_t)strlen(target));
  CHECK(close(source) == 0);
  struct sigaction action = {0};
  action.sa_handler = failed_copy;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  int64_t baseline = native_count();
  for (unsigned round = 0; round < 8; ++round) {
    for (unsigned fault = 0; fault < 4; ++fault) {
      source = open(parent, O_RDONLY | O_DIRECTORY);
      CHECK(source >= 0);
      void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      CHECK(page != MAP_FAILED);
      strcpy(page, "link");
      if (fault == 1)
        CHECK(mprotect(page, 4096, PROT_READ) == 0);
      if (fault == 2)
        CHECK(mprotect(page, 4096, PROT_NONE) == 0);
      memset(output, 0xa5, sizeof(output));
      replacement = -1;
      faulted = 0;
      int jumped = sigsetjmp(destination, 1);
      if (!jumped) {
        const char *path = fault == 2 ? page : "link";
        char *sink = fault == 1 ? page : output;
        size_t size = fault == 3 ? 2 : sizeof(output);
        ssize_t count = readlinkat(source, path, sink, size);
        CHECK(fault == 0 || fault == 3);
        size_t expected = fault == 3 ? 2 : strlen(target);
        CHECK(count == (ssize_t)expected);
        CHECK(!memcmp(output, target, expected) &&
              (unsigned char)output[expected] == 0xa5);
        CHECK(close(source) == 0);
      } else {
        CHECK(jumped == 37 && faulted && (fault == 1 || fault == 2));
        CHECK(replacement == source && native_count() == baseline + 1);
        CHECK(readlinkat(replacement, "link", output, sizeof(output)) ==
              (ssize_t)strlen(target));
        CHECK(close(replacement) == 0);
      }
      CHECK(munmap(page, 4096) == 0 && native_count() == baseline);
    }
  }
  source = open(parent, O_RDONLY | O_DIRECTORY);
  CHECK(source >= 0);
  errno = 0;
  CHECK(readlinkat(source, "link", output, (size_t)-1) == -1 &&
        errno == EINVAL);
  CHECK(unlinkat(source, "link", 0) == 0 && close(source) == 0);
  CHECK(rmdir(parent) == 0 && native_count() == baseline);
  puts("path-io: PASS 32 input/copyout/truncation cases, FD reuse and "
       "reference recovery");
  return 0;
}
