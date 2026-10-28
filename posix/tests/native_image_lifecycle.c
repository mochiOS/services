/* Run with the actual mochiOS CRT/runtime; the parent checks output from exec'd
   children, so teardown order and _exit behavior cannot be hidden by the CRT.
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "image-lifecycle: FAIL line=%d errno=%d: %s\n",          \
              __LINE__, errno, #x);                                            \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static char trace[8];
static unsigned int trace_length;
static int child_mode;
static void preinitialize(void) { trace[trace_length++] = 'P'; }
__attribute__((used, section(".preinit_array"))) static void (
        *const preinitializer)(void) = preinitialize;
__attribute__((constructor(101))) static void initialize_first(void) {
  trace[trace_length++] = 'A';
}
__attribute__((constructor(202))) static void initialize_second(void) {
  trace[trace_length++] = 'B';
}
static void emit(char value) {
  if (child_mode && write(STDOUT_FILENO, &value, 1) != 1)
    _exit(98);
}
__attribute__((destructor(101))) static void finalize_first(void) { emit('a'); }
__attribute__((destructor(202))) static void finalize_second(void) {
  emit('b');
}
static void exit_first(void) { emit('X'); }
static void exit_second(void) { emit('Y'); }

static int check_exec(const char *path, const char *mode,
                      const char *expected) {
  int descriptors[2];
  CHECK(pipe(descriptors) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    close(descriptors[0]);
    if (dup2(descriptors[1], STDOUT_FILENO) < 0)
      _exit(96);
    close(descriptors[1]);
    char *arguments[] = {(char *)path, (char *)mode, NULL};
    char *environment[] = {NULL};
    execve(path, arguments, environment);
    _exit(97);
  }
  CHECK(close(descriptors[1]) == 0);
  char output[32];
  size_t length = 0;
  for (;;) {
    CHECK(length < sizeof(output));
    ssize_t count =
        read(descriptors[0], output + length, sizeof(output) - length);
    if (count < 0 && errno == EINTR)
      continue;
    CHECK(count >= 0);
    if (count == 0)
      break;
    length += (size_t)count;
  }
  CHECK(close(descriptors[0]) == 0);
  int status;
  CHECK(waitpid(child, &status, 0) == child);
  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  if (length != strlen(expected) || memcmp(output, expected, length) != 0) {
    fprintf(stderr, "image-lifecycle: expected=%s observed=%.*s\n", expected,
            (int)length, output);
    return 1;
  }
  return 0;
}

int main(int argc, char **arguments) {
  CHECK(trace_length == 3 && memcmp(trace, "PAB", 3) == 0);
  if (argc == 2 && (strcmp(arguments[1], "--normal") == 0 ||
                    strcmp(arguments[1], "--immediate") == 0)) {
    child_mode = 1;
    CHECK(write(STDOUT_FILENO, trace, trace_length) == (ssize_t)trace_length);
    CHECK(atexit(exit_first) == 0 && atexit(exit_second) == 0);
    emit('M');
    if (strcmp(arguments[1], "--immediate") == 0)
      _exit(0);
    return 0;
  }
  CHECK(argc == 2);
  CHECK(strcmp(arguments[1], "--expect-euid=0") == 0 ||
        strcmp(arguments[1], "--expect-euid=501") == 0);
  CHECK(geteuid() == (strcmp(arguments[1], "--expect-euid=0") == 0 ? 0 : 501));
  alarm(120);
  const char *executable = (const char *)getauxval(AT_EXECFN);
  CHECK(executable && executable[0] == '/');
  CHECK(check_exec(executable, "--normal", "PABMYXba") == 0);
  puts("image-lifecycle: PASS preinit, priority init, atexit and reverse fini");
  CHECK(check_exec(executable, "--immediate", "PABM") == 0);
  puts("image-lifecycle: PASS _exit skips atexit and finalizers");
  return 0;
}
