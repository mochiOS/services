#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      printf("shm-write-limit: FAIL line=%d errno=%d\n", __LINE__, errno);     \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static volatile sig_atomic_t sw_signals;
static void sw_handler(int signal) {
  if (signal == SIGXFSZ)
    ++sw_signals;
}

int main(void) {
  int file =
      shm_open("/native-shm-write-limit", O_CREAT | O_EXCL | O_RDWR, 0600);
  int append = shm_open("/native-shm-write-limit", O_RDWR, 0);
  int other = shm_open("/native-shm-write-limit", O_RDWR, 0);
  int readonly = shm_open("/native-shm-write-limit", O_RDONLY, 0);
  CHECK(file >= 0 && append >= 0 && other >= 0 && readonly >= 0 &&
        shm_unlink("/native-shm-write-limit") == 0);
  int alias = dup(file);
  CHECK(alias >= 0 && write(file, "abcdefgh", 8) == 8 &&
        lseek(file, 3, SEEK_SET) == 3);
  struct rlimit original, limit;
  CHECK(getrlimit(RLIMIT_FSIZE, &original) == 0);
  struct sigaction action = {0}, previous;
  action.sa_handler = sw_handler;
  CHECK(sigemptyset(&action.sa_mask) == 0 &&
        sigaction(SIGXFSZ, &action, &previous) == 0);
  limit = original;
  limit.rlim_cur = 5;
  CHECK(setrlimit(RLIMIT_FSIZE, &limit) == 0);
  CHECK(pwrite(file, "XYZW", 4, 3) == 2 && sw_signals == 0 &&
        lseek(alias, 0, SEEK_CUR) == 3);
  CHECK(write(file, "QRST", 4) == 2 && lseek(alias, 0, SEEK_CUR) == 5);
  char bytes[65] = {0};
  CHECK(pread(file, bytes, 8, 0) == 8 && !memcmp(bytes, "abcQRfgh", 8));
  errno = 0;
  CHECK(write(alias, "!", 1) == -1 && errno == EFBIG && sw_signals == 1);
  CHECK(write(file, NULL, 0) == 0 && pwrite(file, NULL, 0, 99) == 0 &&
        sw_signals == 1);
  errno = 0;
  CHECK(write(readonly, "!", 1) == -1 && errno == EBADF && sw_signals == 1);
  errno = 0;
  CHECK(pwrite(file, "!", 1, -1) == -1 && errno == EINVAL && sw_signals == 1);
  limit.rlim_cur = 10;
  CHECK(setrlimit(RLIMIT_FSIZE, &limit) == 0);
  CHECK(fcntl(append, F_SETFL, O_APPEND) == 0 &&
        fcntl(other, F_SETFL, O_APPEND) == 0);
  CHECK(write(append, "WXYZ", 4) == 2 && lseek(append, 0, SEEK_CUR) == 10 &&
        sw_signals == 1);
  errno = 0;
  CHECK(write(append, "!", 1) == -1 && errno == EFBIG && sw_signals == 2);
  CHECK(ftruncate(file, 8) == 0);
  struct iovec vectors[2] = {{"1", 1}, {"234", 3}};
  CHECK(writev(append, vectors, 2) == 2 && sw_signals == 2);
  CHECK(pwrite(append, "Z", 1, 0) == 1 && lseek(append, 0, SEEK_CUR) == 10);
  CHECK(pread(file, bytes, 1, 0) == 1 && bytes[0] == 'Z');
  CHECK(ftruncate(file, 0) == 0 && lseek(file, 0, SEEK_SET) == 0);
  limit.rlim_cur = 5000;
  CHECK(setrlimit(RLIMIT_FSIZE, &limit) == 0);
  char *large = malloc(10000);
  CHECK(large != NULL);
  memset(large, 'L', 10000);
  CHECK(write(file, large, 10000) == 5000 && sw_signals == 2 &&
        lseek(alias, 0, SEEK_CUR) == 5000);
  errno = 0;
  CHECK(write(file, "!", 1) == -1 && errno == EFBIG && sw_signals == 3);
  CHECK(pwrite(file, "abcd", 4, 4998) == 2 &&
        lseek(alias, 0, SEEK_CUR) == 5000 && sw_signals == 3);
  free(large);
  CHECK(ftruncate(file, 0) == 0);
  limit.rlim_cur = 64;
  CHECK(setrlimit(RLIMIT_FSIZE, &limit) == 0);
  int channel[2];
  CHECK(pipe(channel) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    close(channel[0]);
    unsigned char count = 0;
    while (write(other, "C", 1) == 1) {
      if (++count > 64)
        _exit(42);
    }
    if (errno != EFBIG || write(channel[1], &count, 1) != 1)
      _exit(41);
    _exit(0);
  }
  CHECK(close(channel[1]) == 0);
  unsigned count = 0;
  off_t before;
  for (;;) {
    before = lseek(append, 0, SEEK_CUR);
    ssize_t written = write(append, "P", 1);
    if (written < 0)
      break;
    CHECK(written == 1);
    ++count;
    CHECK(count <= 64);
  }
  CHECK(errno == EFBIG && lseek(append, 0, SEEK_CUR) == before);
  unsigned char child_count;
  CHECK(read(channel[0], &child_count, 1) == 1 && count + child_count == 64);
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  struct stat metadata;
  CHECK(fstat(file, &metadata) == 0 && metadata.st_size == 64 &&
        pread(file, bytes, 64, 0) == 64);
  for (unsigned i = 0; i < 64; ++i)
    CHECK(bytes[i] == 'P' || bytes[i] == 'C');
  CHECK(setrlimit(RLIMIT_FSIZE, &original) == 0 &&
        sigaction(SIGXFSZ, &previous, NULL) == 0);
  CHECK(close(channel[0]) == 0 && close(file) == 0 && close(alias) == 0 &&
        close(append) == 0 && close(other) == 0 && close(readonly) == 0);
  puts("shm-write-limit: PASS write/pwrite/writev prefixes, append "
       "independence, shared cursors, multi-chunk bounds, zero-byte operations "
       "and concurrent cross-process append");
  return 0;
}
