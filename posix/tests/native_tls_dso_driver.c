#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "dso-tls-driver: FAIL line=%d errno=%d: %s\n", __LINE__, \
              errno, #x);                                                      \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static int execute(int fd, char *identity) {
  pid_t child = fork();
  CHECK(child >= 0);
  if (!child) {
    char *arguments[] = {"unrelated-argv-zero", identity, NULL};
    char *environment[] = {NULL};
    if (fd < 0)
      execve("/system/tests/tls-root", arguments, environment);
    else
      fexecve(fd, arguments, environment);
    fprintf(stderr, "dso-tls-driver: exec failed errno=%d\n", errno);
    _exit(99);
  }
  int status;
  CHECK(waitpid(child, &status, 0) == child);
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 42)
    fprintf(stderr, "dso-tls-driver: wait status=%d\n", status);
  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 42);
  return 0;
}
int main(int argc, char **arguments) {
  CHECK(argc == 2);
  alarm(240);
  CHECK(execute(-1, arguments[1]) == 0);
  int input = open("/system/tests/tls-root", O_RDONLY);
  CHECK(input >= 0);
  const char *path = "/tmp/tls-root-256";
  unlink(path);
  int output = open(path, O_WRONLY | O_CREAT | O_EXCL, 0755);
  CHECK(output >= 0);
  char buffer[4096];
  for (;;) {
    ssize_t count = read(input, buffer, sizeof(buffer));
    CHECK(count >= 0);
    if (!count)
      break;
    for (ssize_t at = 0; at < count;) {
      ssize_t n = write(output, buffer + at, (size_t)(count - at));
      CHECK(n > 0);
      at += n;
    }
  }
  CHECK(close(input) == 0 && close(output) == 0);
  input = open(path, O_RDONLY);
  CHECK(input >= 0 && unlink(path) == 0 && lseek(input, 7, SEEK_SET) == 7);
  CHECK(execute(input, arguments[1]) == 0);
  CHECK(lseek(input, 0, SEEK_CUR) == 7 && close(input) == 0);
  puts("dso-tls-driver: PASS pathname and unlinked-FD exec with retained "
       "cursor");
  return 0;
}
