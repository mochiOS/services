/* Real mochiOS integration: run in a process with existing read/exec authority.
 * No writable directory, extra capability, or path permission is required. */
#define _GNU_SOURCE 1
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
enum { KEEP = 40, ALIAS = 41, CLOSE_ON_EXEC = 42 };
#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "fd-exec: FAIL line=%d errno=%d: %s\n", __LINE__, errno, \
              #condition);                                                     \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static int replacement(void) {
  CHECK(fcntl(KEEP, F_GETFD) == 0 && fcntl(ALIAS, F_GETFD) == 0);
  errno = 0;
  CHECK(fcntl(CLOSE_ON_EXEC, F_GETFD) == -1 && errno == EBADF);
  CHECK((fcntl(KEEP, F_GETFL) & (O_ACCMODE | O_NONBLOCK)) ==
        (O_RDONLY | O_NONBLOCK));
  CHECK(lseek(KEEP, 0, SEEK_CUR) == 2);
  char byte = 0;
  CHECK(read(KEEP, &byte, 1) == 1 && byte == 'L');
  CHECK(lseek(ALIAS, 0, SEEK_CUR) == 3);
  CHECK(read(ALIAS, &byte, 1) == 1 && byte == 'F');
  // File status is shared with the parent's OFD; descriptor flags are local.
  CHECK(fcntl(ALIAS, F_SETFL, 0) == 0);
  CHECK(fcntl(ALIAS, F_SETFD, FD_CLOEXEC) == 0);
  CHECK(fcntl(KEEP, F_GETFD) == 0);
  errno = 0;
  CHECK(write(KEEP, "x", 1) == -1 && errno == EBADF);
  CHECK(close(KEEP) == 0);
  CHECK(read(ALIAS, &byte, 1) == 1 && byte == ELFCLASS64);
  CHECK(close(ALIAS) == 0);
  fputs("fd-exec: replacement PASS retained aliases, CLOEXEC and read-only "
        "access\n",
        stderr);
  return 0;
}

int main(int argc, char **argv, char **envp) {
  if (argc == 2 && strcmp(argv[1], "--replacement") == 0)
    return replacement();
  while (*envp)
    ++envp;
  const uintptr_t *aux = (const uintptr_t *)(envp + 1);
  const char *executable = NULL;
  for (; aux[0] != AT_NULL; aux += 2)
    if (aux[0] == AT_EXECFN)
      executable = (const char *)aux[1];
  CHECK(executable && executable[0] == '/');
  int source = open(executable, O_RDONLY);
  CHECK(source >= 0 && source < KEEP);
  CHECK(dup2(source, KEEP) == KEEP && dup2(source, ALIAS) == ALIAS &&
        dup2(source, CLOSE_ON_EXEC) == CLOSE_ON_EXEC);
  CHECK(close(source) == 0);
  CHECK(fcntl(CLOSE_ON_EXEC, F_SETFD, FD_CLOEXEC) == 0);
  CHECK(lseek(KEEP, 0, SEEK_SET) == 0);
  char byte = 0;
  CHECK(read(KEEP, &byte, 1) == 1 && byte == ELFMAG0);
  CHECK(lseek(ALIAS, 0, SEEK_CUR) == 1);

  char *arguments[] = {argv[0], "--replacement", NULL};
  // A failed exec must retain the caller's complete descriptor table.
  errno = 0;
  CHECK(execve("/system/services/absent-fd-exec-probe", arguments, environ) ==
            -1 &&
        errno == ENOENT);
  CHECK(fcntl(CLOSE_ON_EXEC, F_GETFD) == FD_CLOEXEC);
  CHECK(lseek(ALIAS, 0, SEEK_CUR) == 1);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    if (lseek(ALIAS, 0, SEEK_CUR) != 1 || read(ALIAS, &byte, 1) != 1 ||
        byte != 'E' || fcntl(ALIAS, F_SETFL, O_NONBLOCK) != 0)
      _exit(51);
    execve(executable, arguments, environ);
    _exit(52);
  }
  int status = 0;
  CHECK(waitpid(child, &status, 0) == child);
  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  CHECK(lseek(KEEP, 0, SEEK_CUR) == 5 && lseek(ALIAS, 0, SEEK_CUR) == 5);
  CHECK((fcntl(KEEP, F_GETFL) & O_NONBLOCK) == 0);
  CHECK(fcntl(KEEP, F_GETFD) == 0 && fcntl(ALIAS, F_GETFD) == 0);
  CHECK(fcntl(CLOSE_ON_EXEC, F_GETFD) == FD_CLOEXEC);
  CHECK(pread(ALIAS, &byte, 1, 0) == 1 && byte == ELFMAG0);
  CHECK(lseek(KEEP, 0, SEEK_CUR) == 5);
  CHECK(close(KEEP) == 0 && close(ALIAS) == 0 && close(CLOSE_ON_EXEC) == 0);
  fputs("fd-exec: PASS fork/exec shared offset and status, local FD flags, "
        "failed exec preservation and surviving aliases\n",
        stderr);
  return 0;
}
