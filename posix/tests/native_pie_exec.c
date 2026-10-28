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
      fprintf(stderr, "static-pie: FAIL line=%d errno=%d: %s\n", __LINE__,     \
              errno, #x);                                                      \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static int check_child(pid_t child) {
  int status = 0;
  CHECK(child > 0 && waitpid(child, &status, 0) == child);
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 42)
    fprintf(stderr, "static-pie: child status=%d\n", status);
  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 42);
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
int main(int argc, char **arguments) {
  if (argc == 2 && strcmp(arguments[1], "--path-reexec") == 0)
    return 0;
  int standalone = argc == 2 &&
                   strncmp(arguments[1], "--expect-euid=", 14) == 0;
  if (standalone) {
    CHECK(strcmp(arguments[1], "--expect-euid=0") == 0 ||
          strcmp(arguments[1], "--expect-euid=501") == 0);
    CHECK(geteuid() == (strcmp(arguments[1], "--expect-euid=0") == 0 ? 0 : 501));
  }
  alarm(180);
#ifdef MOCHIOS_STARTUP_IDENTITY
  char ids[4][24];
  snprintf(ids[0], sizeof ids[0], "%lu", (unsigned long)getuid());
  snprintf(ids[1], sizeof ids[1], "%lu", (unsigned long)geteuid());
  snprintf(ids[2], sizeof ids[2], "%lu", (unsigned long)getgid());
  snprintf(ids[3], sizeof ids[3], "%lu", (unsigned long)getegid());
#endif
  char *argv[] = {"static-pie",
#ifdef MOCHIOS_STARTUP_IDENTITY
    ids[0], ids[1], ids[2], ids[3],
#endif
    NULL};
  char *env[] = {
#ifdef MOCHIOS_STARTUP_IDENTITY
    "LD_LIBRARY_PATH=", "LD_PRELOAD=", "LD_AUDIT=", "MOCHIOS_STARTUP_MARKER=preserved",
#endif
    NULL};
  errno = 0;
  CHECK(execve("/system/tests/interpreted-pie-204", argv, env) == -1 &&
        errno == ENOEXEC);
  int64_t before = handles();
  CHECK(before >= 0);
  for (int i = 0; i < 12; i++) {
    errno = 0;
    CHECK(execve("/system/tests/interpreted-pie-204", argv, env) == -1 &&
          errno == ENOEXEC);
  }
  CHECK(handles() == before);
  puts("static-pie: PASS unsupported interpreter preserves image and handles");
#ifdef MOCHIOS_SHARED_SCOPE
  struct stat library_status;
  CHECK(stat("/system/tests/libscope.so", &library_status) == 0);
  CHECK((library_status.st_mode & 0777) == 0644);
  before = handles();
  for (int i = 0; i < 12; ++i) {
    errno = 0;
    CHECK(execve("/system/tests/missing-library-root", argv, env) == -1 && errno == ENOENT);
  }
  CHECK(handles() == before);
  puts("dynamic-pie: PASS missing dependency preserves image and handles");
#ifdef MOCHIOS_LIBRARY_SEARCH
  char *search_environment[] = {"LD_LIBRARY_PATH=/system/tests",
#ifdef MOCHIOS_STARTUP_IDENTITY
    "LD_PRELOAD=", "LD_AUDIT=", "MOCHIOS_STARTUP_MARKER=preserved",
#endif
    NULL};
  int secure = getuid() != geteuid() || getgid() != getegid();
  pid_t search_child = fork();
  CHECK(search_child >= 0);
  if (search_child == 0) {
    execve("/system/tests/environment-library-root", argv, search_environment);
    if (secure && errno == ENOENT) _exit(42);
    fprintf(stderr, "library-search: FAIL secure=%d errno=%d\n", secure, errno);
    _exit(99);
  }
  CHECK(check_child(search_child) == 0);
  puts("library-search: PASS environment lookup and secure identity exclusion");
#endif
#endif
  for (int i = 0; i < 3; i++) {
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
      execve("/system/tests/static-pie-204", argv, env);
      fprintf(stderr, "static-pie: exec errno=%d\n", errno);
      _exit(99);
    }
    CHECK(check_child(child) == 0);
  }
  puts("static-pie: PASS pathname PIE, relative pointers, BSS, bias and "
       "original TLS auxiliary headers");
#ifdef MOCHIOS_SHARED_SCOPE
  puts("dynamic-pie: PASS pathname exec, shared function and root preemption");
#ifdef MOCHIOS_STARTUP_IDENTITY
  puts("entry-identity: PASS literal IDs and secure vector before CRT");
#endif
#endif
  const char *path = "/tmp/static-pie-204";
  unlink(path);
  int input = open("/system/tests/static-pie-204", O_RDONLY),
      output = open(path, O_CREAT | O_EXCL | O_RDWR, 0700);
  CHECK(input >= 0 && output >= 0);
  char bytes[4096];
  ssize_t n;
  while ((n = read(input, bytes, sizeof bytes)) > 0) {
    ssize_t offset = 0;
    while (offset < n) {
      ssize_t count = write(output, bytes + offset, n - offset);
      CHECK(count > 0);
      offset += count;
    }
  }
  CHECK(n == 0 && close(input) == 0 && close(output) == 0);
  int image = open(path, O_RDONLY | O_CLOEXEC);
  CHECK(image >= 0 && lseek(image, 13, SEEK_SET) == 13 && unlink(path) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    fexecve(image, argv, env);
    fprintf(stderr, "static-pie: fexecve errno=%d\n", errno);
    _exit(99);
  }
  CHECK(check_child(child) == 0 && lseek(image, 0, SEEK_CUR) == 13 &&
        close(image) == 0);
  puts("static-pie: PASS unregistered unlinked descriptor PIE and unchanged "
       "shared offset");
  if (standalone) {
    alarm(0);
    return 0;
  }
  execve("/system/tests/execve-regression-204", argv, environ);
  fprintf(stderr, "static-pie: regression launch errno=%d\n", errno);
  return 1;
}
