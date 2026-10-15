/* Real newlib -> POSIX -> filesystem -> provider-memory update integration. */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "file-extent-update: FAIL line %u errno=%d: %s\n",       \
              __LINE__, errno, #x);                                            \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static void outside_extent(int signal_number) {
  _exit(signal_number == SIGBUS ? 42 : 43);
}

int main(void) {
  char path[] = "/tmp/extent-update-XXXXXX";
  int file = mkstemp(path);
  CHECK(file >= 0);
  unsigned char bytes[8192];
  memset(bytes, 'a', 4096);
  memset(bytes + 4096, 'b', 4096);
  CHECK(write(file, bytes, sizeof(bytes)) == (ssize_t)sizeof(bytes));
  int alias = open(path, O_RDWR);
  CHECK(alias >= 0);
  volatile unsigned char *private_bytes =
      mmap(NULL, sizeof(bytes), PROT_READ | PROT_WRITE, MAP_PRIVATE, file, 0);
  volatile unsigned char *shared =
      mmap(NULL, sizeof(bytes), PROT_READ | PROT_WRITE, MAP_SHARED, alias, 0);
  CHECK(private_bytes != MAP_FAILED && shared != MAP_FAILED);
  CHECK(private_bytes[0] == 'a' && private_bytes[8191] == 'b');
  CHECK(shared[0] == 'a' && shared[8191] == 'b');
  private_bytes[0] = 'P';
  shared[17] = 'S';
  CHECK(ftruncate(alias, 5000) == 0);
  CHECK(private_bytes[0] == 'P' && private_bytes[17] == 'a');
  CHECK(shared[0] == 'a' && shared[17] == 'S');
  CHECK(private_bytes[4999] == 'b' && private_bytes[5000] == 0 &&
        private_bytes[8191] == 0);
  CHECK(shared[4999] == 'b' && shared[5000] == 0 && shared[8191] == 0);
  CHECK(msync((void *)shared, sizeof(bytes), MS_SYNC) == 0);
  struct stat state;
  CHECK(fstat(file, &state) == 0 && state.st_size == 5000);
  CHECK(pread(file, bytes, sizeof(bytes), 0) == 5000);
  CHECK(bytes[0] == 'a' && bytes[17] == 'S' && bytes[4999] == 'b');
  CHECK(ftruncate(file, 4096) == 0);
  int truncating = open(path, O_RDWR | O_TRUNC);
  CHECK(truncating >= 0);
  CHECK(fstat(file, &state) == 0 && state.st_size == 0);
  CHECK(ftruncate(truncating, sizeof(bytes)) == 0);
  for (size_t i = 0; i < sizeof(bytes); ++i) {
    CHECK(shared[i] == 0 && private_bytes[i] == 0);
  }
  CHECK(pwrite(file, "N", 1, 0) == 1);
  CHECK(shared[0] == 'N' && private_bytes[0] == 0);
  CHECK(unlink(path) == 0);
  CHECK(ftruncate(alias, 17) == 0);
  CHECK(fstat(truncating, &state) == 0 && state.st_size == 17);
  CHECK(shared[0] == 'N' && shared[17] == 0);
  puts("file-extent-update: storage/cache/alias checks passed; checking fork "
       "and EOF fault");
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    struct sigaction action = {0};
    action.sa_handler = outside_extent;
    if (sigemptyset(&action.sa_mask) || sigaction(SIGBUS, &action, NULL) ||
        sigaction(SIGSEGV, &action, NULL))
      _exit(44);
    volatile unsigned char invalid = shared[4096];
    (void)invalid;
    _exit(45);
  }
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 42);
  CHECK(close(truncating) == 0 && close(alias) == 0 && close(file) == 0);
  CHECK(munmap((void *)private_bytes, sizeof(bytes)) == 0);
  CHECK(munmap((void *)shared, sizeof(bytes)) == 0);
  puts("file-extent-update: PASS ftruncate, O_TRUNC, shared/private aliases, "
       "EOF faults, regrowth and unlinked handles");
  return 0;
}
