/* Actual mochiOS newlib CRT, stdio, atexit and exit with captured DSOs. */
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
      fprintf(stderr, "crt-dso: FAIL line=%d errno=%d: %s\n", __LINE__, errno, \
              #x);                                                             \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static char trace[64];
static size_t trace_length;
void lifecycle_record(char event) {
  if (trace_length >= sizeof(trace))
    _exit(91);
  trace[trace_length++] = event;
  if (getenv("LIFECYCLE_CAPTURE") && write(STDOUT_FILENO, &event, 1) != 1)
    _exit(92);
}
void lifecycle_checkpoint(char point) {
  if (point == '3' && getenv("LIFECYCLE_EARLY_FIRST"))
    exit(0);
}
static void preinitialize(void) { lifecycle_record('P'); }
__attribute__((used, section(".preinit_array"))) static void (
        *const preinitializer)(void) = preinitialize;
void lifecycle_init(void) { lifecycle_record('r'); }
void lifecycle_fini(void) { lifecycle_record('R'); }
static void constructor_exit(void) { lifecycle_record('T'); }
__attribute__((constructor(101))) static void initialize_first(void) {
  lifecycle_record('7');
  if (atexit(constructor_exit))
    _exit(93);
}
extern void lifecycle_cross_init(void);
__attribute__((used, section(".init_array.00150"))) static void (
        *const cross_initializer)(void) = lifecycle_cross_init;
__attribute__((constructor(202))) static void initialize_second(void) {
  lifecycle_record('8');
}
__attribute__((destructor(101))) static void finalize_first(void) {
  lifecycle_record('I');
}
__attribute__((destructor(202))) static void finalize_second(void) {
  lifecycle_record('J');
}
static void first_exit(void) { lifecycle_record('X'); }
static void second_exit(void) { lifecycle_record('Y'); }
extern int lifecycle_first(void);
extern int lifecycle_second(void);
static int run_child(const char *path, const char *mode, const char *expected) {
  int descriptors[2];
  CHECK(pipe(descriptors) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    close(descriptors[0]);
    if (dup2(descriptors[1], STDOUT_FILENO) < 0)
      _exit(94);
    close(descriptors[1]);
    char *arguments[] = {"unrelated-argv-zero", (char *)mode, NULL};
    char *environment[] = {"LIFECYCLE_CAPTURE=1",
                           strcmp(mode, "--partial") == 0
                               ? "LIFECYCLE_EARLY_FIRST=1"
                               : "KEEP=original",
                           NULL};
    execve(path, arguments, environment);
    _exit(95);
  }
  CHECK(close(descriptors[1]) == 0);
  char output[128];
  size_t length = 0;
  for (;;) {
    CHECK(length < sizeof(output));
    ssize_t count =
        read(descriptors[0], output + length, sizeof(output) - length);
    if (count < 0 && errno == EINTR)
      continue;
    CHECK(count >= 0);
    if (!count)
      break;
    length += (size_t)count;
  }
  CHECK(close(descriptors[0]) == 0);
  int status;
  CHECK(waitpid(child, &status, 0) == child);
  if (status)
    fprintf(stderr, "crt-dso: wait status=%d\n", status);
  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  if (length != strlen(expected) || memcmp(output, expected, length)) {
    fprintf(stderr, "crt-dso: mode=%s expected=%s observed=%.*s\n", mode,
            expected, (int)length, output);
    return 1;
  }
  return 0;
}
int main(int argc, char **arguments) {
  CHECK(trace_length == 14 && memcmp(trace, "Pl12f34s56r7X8", 14) == 0);
  CHECK(lifecycle_first() == 2 && lifecycle_second() == 3);
  CHECK(getauxval(AT_ENTRY) != 0 && getauxval(AT_PHDR) != 0);
  if (argc == 2 && (strcmp(arguments[1], "--observe") == 0 ||
                    strcmp(arguments[1], "--immediate") == 0)) {
    lifecycle_record('M');
    CHECK(atexit(first_exit) == 0 && atexit(second_exit) == 0);
    if (strcmp(arguments[1], "--immediate") == 0)
      _exit(0);
    return 0;
  }
  CHECK(argc == 2 && (strcmp(arguments[1], "--expect-euid=0") == 0 ||
                      strcmp(arguments[1], "--expect-euid=501") == 0));
  CHECK(geteuid() == (strcmp(arguments[1], "--expect-euid=0") == 0 ? 0 : 501));
  alarm(180);
  const char *path = (const char *)getauxval(AT_EXECFN);
  CHECK(path && path[0] == '/');
  CHECK(run_child(path, "--observe", "Pl12f34s56r7X8MYXTJIRHGSDCFBAL") == 0);
  puts("crt-dso: PASS real CRT initialization, stdio, atexit and reverse "
       "teardown");
  CHECK(run_child(path, "--immediate", "Pl12f34s56r7X8M") == 0);
  puts("crt-dso: PASS _exit skips all teardown");
  CHECK(run_child(path, "--partial", "Pl12f3DCFBAL") == 0);
  puts("crt-dso: PASS exit during constructor finalizes only started objects");
  return 0;
}
