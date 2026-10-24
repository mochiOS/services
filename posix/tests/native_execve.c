#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "execve-object: FAIL line=%d errno=%d: %s\n", __LINE__,  \
              errno, #x);                                                      \
      return 1;                                                                \
    }                                                                          \
  } while (0)
#ifdef EXECVE_PAYLOAD
int main(int argc, char **argv) {
  alarm(60);
  CHECK(argc == 2 && strcmp(argv[0], "execve-payload") == 0);
  CHECK(getenv("EXECVE_CASE") && strcmp(getenv("EXECVE_CASE"), argv[1]) == 0);
  CHECK(geteuid() != 0);
  CHECK(getenv("EXECVE_EUID") &&
        geteuid() == (uid_t)atoi(getenv("EXECVE_EUID")));
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0)
    _exit(37);
  int status = 0;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 37);
  printf("execve-object: payload %s and nested fork/wait verified\n", argv[1]);
  return 0;
}
#else
static int copy_image(const char *source, const char *target) {
  int in = open(source, O_RDONLY),
      out = open(target, O_CREAT | O_EXCL | O_RDWR, 0700);
  CHECK(in >= 0 && out >= 0);
  char bytes[4096];
  ssize_t n;
  while ((n = read(in, bytes, sizeof bytes)) > 0) {
    ssize_t offset = 0;
    while (offset < n) {
      ssize_t wrote = write(out, bytes + offset, n - offset);
      CHECK(wrote > 0);
      offset += wrote;
    }
  }
  CHECK(n == 0 && close(in) == 0 && close(out) == 0);
  return 0;
}
static int64_t handles(void) {
  uint64_t number = 680;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(0), "S"(0), "d"(0)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
static int run(const char *path, const char *directory, const char *label,
               int search) {
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(setenv("EXECVE_CASE", label, 1) == 0);
    if (directory)
      CHECK(chdir(directory) == 0);
    if (search)
      CHECK(setenv("PATH", directory, 1) == 0);
    // Exercise execute-only admission without uid zero's read-mode bypass.
    if (geteuid() == 0)
      CHECK(seteuid(501) == 0);
    char uid[32];
    snprintf(uid, sizeof uid, "%u", (unsigned)geteuid());
    CHECK(setenv("EXECVE_EUID", uid, 1) == 0);
    char *args[] = {"execve-payload", (char *)label, NULL};
    if (search)
      execvp(path, args);
    else
      execve(path, args, environ);
    fprintf(stderr, "execve-object: unexpected return case=%s errno=%d\n",
            label, errno);
    _exit(99);
  }
  int status = 0;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  printf("execve-object: PASS %s\n", label);
  return 0;
}
int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--path-reexec") == 0)
    return 0;
  alarm(180);
  char *args[] = {"old-image", NULL};
  char empty[] = "";
  errno = 0;
  CHECK(execve(empty, args, environ) == -1 && errno == ENOENT);
  volatile uintptr_t bad = 1;
  errno = 0;
  CHECK(execve((const char *)bad, args, environ) == -1 && errno == EFAULT);
  errno = 0;
  CHECK(execve("/tmp/no-execve-image-203", args, environ) == -1 &&
        errno == ENOENT);
  errno = 0;
  CHECK(execve("/tmp", args, environ) == -1 && errno == EACCES);
  const char *invalid = "/tmp/execve-invalid-203";
  unlink(invalid);
  int fd = open(invalid, O_CREAT | O_EXCL | O_RDWR, 0600);
  CHECK(fd >= 0);
  CHECK(write(fd, "bad image", 9) == 9 && close(fd) == 0);
  errno = 0;
  CHECK(execve(invalid, args, environ) == -1 && errno == EACCES);
  CHECK(chmod(invalid, 0700) == 0);
  errno = 0;
  CHECK(execve(invalid, args, environ) == -1 && errno == ENOEXEC);
  int64_t before = handles();
  CHECK(before >= 0);
  for (int i = 0; i < 16; i++) {
    errno = 0;
    CHECK(execve(invalid, args, environ) == -1 && errno == ENOEXEC);
  }
  CHECK(handles() == before && unlink(invalid) == 0);
  puts("execve-object: PASS failed exec preserves image and releases opened "
       "handles");
  char directory[512] = "/tmp/execve-203";
  CHECK(mkdir(directory, 0755) == 0);
  for (int i = 0; i < 5; i++) {
    size_t n = strlen(directory);
    CHECK(snprintf(
              directory + n, sizeof directory - n,
              "/component-%d-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk",
              i) > 0);
    CHECK(mkdir(directory, 0755) == 0);
  }
  char image[600];
  CHECK(snprintf(image, sizeof image, "%s/program-\xff", directory) > 255);
  CHECK(copy_image("/system/tests/execve-payload-203", image) == 0 &&
        chmod(image, 0111) == 0);
  CHECK(run(image, NULL, "absolute-long-byte-path", 0) == 0);
  CHECK(run("./program-\xff", directory, "relative-byte-path", 0) == 0);
  CHECK(run("program-\xff", directory, "path-search-byte-name", 1) == 0);
  const char *link = "/tmp/execve-link-203";
  CHECK(symlink(image, link) == 0 && run(link, NULL, "symlink-image", 0) == 0 &&
        unlink(link) == 0);
  CHECK(unlink(image) == 0);
  for (int i = 0; i < 5; i++) {
    CHECK(rmdir(directory) == 0);
    char *slash = strrchr(directory, '/');
    CHECK(slash);
    *slash = 0;
  }
  CHECK(rmdir(directory) == 0);
  puts("execve-object: PASS unregistered execute-only ELF and cleanup");
  char *regression[] = {"fexecve-regression", NULL};
  execve("/system/tests/fexecve-regression-203", regression, environ);
  fprintf(stderr, "execve-object: regression launch failed errno=%d\n", errno);
  return 1;
}
#endif
