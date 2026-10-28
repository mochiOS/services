#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "dso-lifecycle: FAIL line=%d errno=%d: %s\n", __LINE__,  \
              errno, #x);                                                      \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static const char *root = "/system/tests/lifecycle-root";
static int check_child(int fd) {
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    char *arguments[] = {"unrelated-argv-zero", NULL};
    char *environment[] = {NULL};
    if (fd >= 0)
      fexecve(fd, arguments, environment);
    else
      execve(root, arguments, environment);
    fprintf(stderr, "dso-lifecycle: exec failed errno=%d\n", errno);
    _exit(99);
  }
  int status;
  CHECK(waitpid(child, &status, 0) == child);
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 42)
    fprintf(stderr, "dso-lifecycle: unexpected wait status=%d\n", status);
  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 42);
  return 0;
}
int main(int argc, char **arguments) {
  CHECK(argc == 2);
  CHECK(strcmp(arguments[1], "--expect-euid=0") == 0 ||
        strcmp(arguments[1], "--expect-euid=501") == 0);
  CHECK(geteuid() == (strcmp(arguments[1], "--expect-euid=0") == 0 ? 0 : 501));
  alarm(180);
  CHECK(check_child(-1) == 0);
  puts("dso-lifecycle: PASS pathname exec, relocated callbacks and once-only "
       "teardown");
  int input = open(root, O_RDONLY);
  CHECK(input >= 0);
  const char *temporary = "/tmp/lifecycle-root-252";
  unlink(temporary);
  int output = open(temporary, O_WRONLY | O_CREAT | O_EXCL, 0755);
  CHECK(output >= 0);
  char buffer[4096];
  for (;;) {
    ssize_t count = read(input, buffer, sizeof(buffer));
    CHECK(count >= 0);
    if (!count)
      break;
    ssize_t position = 0;
    while (position < count) {
      ssize_t written =
          write(output, buffer + position, (size_t)(count - position));
      CHECK(written > 0);
      position += written;
    }
  }
  CHECK(close(input) == 0 && close(output) == 0);
  input = open(temporary, O_RDONLY);
  CHECK(input >= 0 && unlink(temporary) == 0 && lseek(input, 7, SEEK_SET) == 7);
  CHECK(check_child(input) == 0);
  CHECK(lseek(input, 0, SEEK_CUR) == 7 && close(input) == 0);
  puts("dso-lifecycle: PASS unlinked file-handle exec and retained shared "
       "cursor");
  return 0;
}
