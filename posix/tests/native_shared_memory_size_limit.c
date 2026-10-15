#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      printf("shm-size-limit: FAIL line=%d errno=%d\n", __LINE__, errno);      \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static volatile sig_atomic_t sf_signals;
static void sf_handler(int signal) {
  if (signal == SIGXFSZ)
    ++sf_signals;
}

int main(void) {
  int file =
      shm_open("/native-shm-size-limit", O_CREAT | O_EXCL | O_RDWR, 0600);
  int readonly = shm_open("/native-shm-size-limit", O_RDONLY, 0);
  CHECK(file >= 0 && readonly >= 0 &&
        shm_unlink("/native-shm-size-limit") == 0);
  int alias = dup(file);
  CHECK(alias >= 0 && ftruncate(file, 8192) == 0);
  unsigned char *view =
      mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, file, 0);
  CHECK(view != MAP_FAILED);
  view[0] = 31;
  view[6999] = 77;
  CHECK(lseek(file, 3, SEEK_SET) == 3);
  struct rlimit original, limit;
  CHECK(getrlimit(RLIMIT_FSIZE, &original) == 0);
  struct sigaction action = {0}, previous;
  action.sa_handler = sf_handler;
  CHECK(sigemptyset(&action.sa_mask) == 0 &&
        sigaction(SIGXFSZ, &action, &previous) == 0);
  limit = original;
  limit.rlim_cur = 4096;
  CHECK(setrlimit(RLIMIT_FSIZE, &limit) == 0);
  CHECK(ftruncate(file, 8192) == 0 && ftruncate(alias, 7000) == 0 &&
        sf_signals == 0);
  errno = 0;
  CHECK(ftruncate(file, 7001) == -1 && errno == EFBIG && sf_signals == 1);
  struct stat status;
  CHECK(fstat(file, &status) == 0 && status.st_size == 7000);
  CHECK(lseek(alias, 0, SEEK_CUR) == 3 && view[0] == 31 && view[6999] == 77);
  errno = 0;
  CHECK(ftruncate(readonly, 7001) == -1 && errno == EBADF && sf_signals == 1);
  errno = 0;
  CHECK(ftruncate(file, -1) == -1 && errno == EINVAL && sf_signals == 1);
  limit.rlim_cur = 0;
  CHECK(setrlimit(RLIMIT_FSIZE, &limit) == 0);
  CHECK(ftruncate(file, 4096) == 0 && ftruncate(file, 4096) == 0);
  errno = 0;
  CHECK(ftruncate(alias, 4097) == -1 && errno == EFBIG && sf_signals == 2);
  CHECK(ftruncate(file, 0) == 0 && lseek(alias, 0, SEEK_CUR) == 3);
  sigset_t blocked, old_mask, pending;
  CHECK(sigemptyset(&blocked) == 0 && sigaddset(&blocked, SIGXFSZ) == 0);
  CHECK(sigprocmask(SIG_BLOCK, &blocked, &old_mask) == 0);
  errno = 0;
  CHECK(ftruncate(alias, 1) == -1 && errno == EFBIG && sf_signals == 2);
  CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGXFSZ) == 1);
  CHECK(sigprocmask(SIG_SETMASK, &old_mask, NULL) == 0 && sf_signals == 3);
  action.sa_handler = SIG_IGN;
  CHECK(sigaction(SIGXFSZ, &action, NULL) == 0);
  errno = 0;
  CHECK(ftruncate(file, 1) == -1 && errno == EFBIG && sf_signals == 3);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    action.sa_handler = SIG_DFL;
    if (sigaction(SIGXFSZ, &action, NULL) != 0)
      _exit(81);
    (void)ftruncate(file, 1);
    _exit(82);
  }
  int child_status;
  CHECK(waitpid(child, &child_status, 0) == child &&
        WIFSIGNALED(child_status) && WTERMSIG(child_status) == SIGXFSZ);
  CHECK(setrlimit(RLIMIT_FSIZE, &original) == 0 &&
        sigaction(SIGXFSZ, &previous, NULL) == 0);
  CHECK(ftruncate(alias, 8192) == 0 && view[0] == 0 && view[6999] == 0);
  CHECK(munmap(view, 8192) == 0 && close(file) == 0 && close(alias) == 0 &&
        close(readonly) == 0);
  puts("shm-size-limit: PASS bounded growth, shrink above lowered limit, "
       "unlinked aliases, cursor/data preservation and "
       "caught/blocked/ignored/default SIGXFSZ");
  return 0;
}
