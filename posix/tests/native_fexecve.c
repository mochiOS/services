#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "fexecve: FAIL line=%d errno=%d: %s\n", __LINE__, errno, \
              #x);                                                             \
      return 1;                                                                \
    }                                                                          \
  } while (0)
#ifndef FEXECVE_PAYLOAD
static void handler(int signal) { (void)signal; }
#endif
#ifdef FEXECVE_PAYLOAD
static int number(const char *key) {
  const char *s = getenv(key);
  return s ? atoi(s) : -1;
}
int main(int argc, char **argv) {
  alarm(60);
  CHECK(argc == 3 && strcmp(argv[0], "fd-executed") == 0 &&
        strcmp(argv[1], "a b") == 0);
  CHECK((unsigned char)argv[2][0] == 0xff && argv[2][1] == 0);
  CHECK(getenv("FEXECVE_TEST") && strcmp(getenv("FEXECVE_TEST"), "ok") == 0);
  int keep = number("KEEP"), drop = number("DROP"), image = number("IMAGE");
  int ready = number("READY"), go = number("GO");
  CHECK(keep >= 0 && drop >= 0 && image >= 0 && ready >= 0 && go >= 0);
  errno = 0;
  CHECK(fcntl(image, F_GETFD) == -1 && errno == EBADF);
  errno = 0;
  CHECK(fcntl(drop, F_GETFD) == -1 && errno == EBADF);
  CHECK(fcntl(keep, F_GETFD) == 0 && lseek(keep, 0, SEEK_CUR) == 2);
  char c = 0;
  CHECK(read(keep, &c, 1) == 1 && c == 'c');
  struct sigaction action;
  CHECK(sigaction(SIGUSR1, NULL, &action) == 0 && action.sa_handler == SIG_DFL);
  CHECK(sigaction(SIGUSR2, NULL, &action) == 0 && action.sa_handler == SIG_IGN);
  sigset_t mask, pending;
  CHECK(sigprocmask(SIG_SETMASK, NULL, &mask) == 0 &&
        sigismember(&mask, SIGUSR1) == 1);
  CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGUSR1) == 1);
  pid_t nested = fork();
  CHECK(nested >= 0);
  if (nested == 0) {
    _exit(42);
  }
  int nested_status = 0;
  CHECK(waitpid(nested, &nested_status, 0) == nested &&
        WIFEXITED(nested_status) && WEXITSTATUS(nested_status) == 42);
  puts("fexecve: unlinked image fork/wait verified");
  CHECK(write(ready, "P", 1) == 1 && read(go, &c, 1) == 1 && c == 'G');
  CHECK(close(keep) == 0 && close(ready) == 0 && close(go) == 0);
  puts("fexecve: payload verified argv/env, CLOEXEC, shared offset and signal "
       "state");
  return 0;
}
#else
static int copy_image(const char *source, const char *target) {
  int input = open(source, O_RDONLY),
      output = open(target, O_CREAT | O_EXCL | O_RDWR, 0700);
  CHECK(input >= 0 && output >= 0);
  char bytes[4096];
  ssize_t n;
  while ((n = read(input, bytes, sizeof bytes)) > 0) {
    ssize_t offset = 0;
    while (offset < n) {
      ssize_t wrote = write(output, bytes + offset, n - offset);
      CHECK(wrote > 0);
      offset += wrote;
    }
  }
  CHECK(n == 0 && fchmod(output, 0700) == 0 && close(input) == 0 &&
        close(output) == 0);
  return 0;
}
static int64_t native_handles(void) {
  uint64_t number = 680;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(0), "S"(0), "d"(0)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
static int failures(void) {
  char *args[] = {"old-image", NULL}, *env[] = {NULL};
  errno = 0;
  CHECK(fexecve(-1, args, env) == -1 && errno == EBADF);
  int dir = open("/tmp", O_RDONLY | O_DIRECTORY);
  CHECK(dir >= 0);
  errno = 0;
  CHECK(fexecve(dir, args, env) == -1 && errno == EACCES);
  CHECK(close(dir) == 0);
  int pipes[2];
  CHECK(pipe(pipes) == 0);
  errno = 0;
  CHECK(fexecve(pipes[0], args, env) == -1 && errno == EACCES);
  CHECK(close(pipes[0]) == 0 && close(pipes[1]) == 0);
  const char *path = "/tmp/fexecve-bad-201";
  unlink(path);
  int bad = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  CHECK(bad >= 0);
  CHECK(write(bad, "not an ELF", 10) == 10);
  errno = 0;
  CHECK(fexecve(bad, args, env) == -1 && errno == EACCES);
  CHECK(fchmod(bad, 0700) == 0);
  volatile uintptr_t bad_address = 1;
  errno = 0;
  CHECK(fexecve(bad, (char *const *)bad_address, env) == -1 && errno == EFAULT);
  struct sigaction action;
  memset(&action, 0, sizeof action);
  action.sa_handler = handler;
  CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
  int64_t observed = -1;
  for (int i = 0; i < 2; i++) {
    errno = 0;
    CHECK(fexecve(bad, args, env) == -1 && errno == ENOEXEC);
    CHECK(fcntl(bad, F_GETFD) == FD_CLOEXEC && lseek(bad, 0, SEEK_CUR) == 10);
    CHECK(sigaction(SIGUSR1, NULL, &action) == 0 &&
          action.sa_handler == handler);
    int64_t count = native_handles();
    CHECK(count >= 0);
    if (observed >= 0)
      CHECK(observed == count);
    observed = count;
  }
  CHECK(close(bad) == 0 && unlink(path) == 0);
  puts("fexecve: PASS rejected FD/mode/memory/format preserve the old image "
       "and descriptors");
  return 0;
}
int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--path-reexec") == 0)
    return 0;
  alarm(120);
  CHECK(failures() == 0);
  const char *path = "/tmp/fexecve-image-201", *data = "/tmp/fexecve-data-201";
  unlink(path);
  unlink(data);
  CHECK(copy_image("/system/tests/fexecve-payload-201", path) == 0);
  int image = open(path, O_RDONLY | O_CLOEXEC);
  CHECK(image >= 0);
  CHECK(unlink(path) == 0);
  struct stat stat;
  CHECK(fstat(image, &stat) == 0 && stat.st_nlink == 0);
  int drop = open(data, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  CHECK(drop >= 0);
  CHECK(write(drop, "abcdef", 6) == 6 && lseek(drop, 2, SEEK_SET) == 2);
  int keep = dup(drop);
  CHECK(keep >= 0);
  int ready[2], go[2];
  CHECK(pipe(ready) == 0 && pipe(go) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(close(ready[0]) == 0 && close(go[1]) == 0);
    struct flock lock = {0};
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    CHECK(fcntl(keep, F_SETLK, &lock) == 0);
    CHECK(write(ready[1], "L", 1) == 1);
    char c;
    CHECK(read(go[0], &c, 1) == 1 && c == 'E');
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = handler;
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    action.sa_handler = SIG_IGN;
    CHECK(sigaction(SIGUSR2, &action, NULL) == 0);
    sigset_t blocked;
    CHECK(sigemptyset(&blocked) == 0 && sigaddset(&blocked, SIGUSR1) == 0);
    CHECK(sigprocmask(SIG_BLOCK, &blocked, NULL) == 0 &&
          kill(getpid(), SIGUSR1) == 0);
    char k[32], d[32], im[32], r[32], g[32];
    snprintf(k, sizeof k, "KEEP=%d", keep);
    snprintf(d, sizeof d, "DROP=%d", drop);
    snprintf(im, sizeof im, "IMAGE=%d", image);
    snprintf(r, sizeof r, "READY=%d", ready[1]);
    snprintf(g, sizeof g, "GO=%d", go[0]);
    char *args[] = {"fd-executed", "a b", "\xff", NULL};
    char *env[] = {"FEXECVE_TEST=ok", k, d, im, r, g, NULL};
    fexecve(image, args, env);
    fprintf(stderr, "fexecve: unexpected return errno=%d\n", errno);
    _exit(99);
  }
  CHECK(close(ready[1]) == 0 && close(go[0]) == 0);
  char c;
  CHECK(read(ready[0], &c, 1) == 1 && c == 'L');
  struct flock lock = {0};
  lock.l_type = F_WRLCK;
  lock.l_whence = SEEK_SET;
  errno = 0;
  CHECK(fcntl(drop, F_SETLK, &lock) == -1 &&
        (errno == EAGAIN || errno == EACCES));
  CHECK(write(go[1], "E", 1) == 1);
  CHECK(read(ready[0], &c, 1) == 1 && c == 'P');
  CHECK(fcntl(drop, F_SETLK, &lock) == 0);
  lock.l_type = F_UNLCK;
  CHECK(fcntl(drop, F_SETLK, &lock) == 0);
  CHECK(lseek(drop, 0, SEEK_CUR) == 3);
  CHECK(write(go[1], "G", 1) == 1);
  int status = 0;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  CHECK(close(image) == 0 && close(drop) == 0 && close(keep) == 0);
  CHECK(close(ready[0]) == 0 && close(go[1]) == 0 && unlink(data) == 0);
  puts("fexecve: PASS unregistered unlinked ELF, argv/env, CLOEXEC, offsets, "
       "signals and record locks");
  child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    char *args[] = {"path-reexec", "--path-reexec", NULL}, *env[] = {NULL};
    execve("/system/services/compositor.service", args, env);
    _exit(98);
  }
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  puts("fexecve: PASS pathname execve uses the shared startup path");
  return 0;
}
#endif
