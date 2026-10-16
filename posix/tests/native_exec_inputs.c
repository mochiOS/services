#define _GNU_SOURCE
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static unsigned operation;
static unsigned char *pages;
static sigjmp_buf jump;
static char *too_many[256];
static char too_large[4097];
static const char executable[] = "/system/services/compositor.service";
#define CHECK(test)                                                            \
  do {                                                                         \
    if (!(test)) {                                                             \
      fprintf(stderr, "exec-inputs: FAIL op=%u line=%d errno=%d: %s\n",        \
              operation, __LINE__, errno, #test);                              \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static int64_t handles(void) {
  uint64_t number = 680;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(0), "S"(0), "d"(0)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
static int invalid_exec(void) {
  char *valid[] = {"exec-inputs", NULL};
  char *bad_text[] = {(char *)pages + 4096, NULL};
  char *boundary_text[] = {(char *)pages + 4096 - 16, NULL};
  char *large[] = {too_large, NULL};
  char *empty[] = {"", NULL};
  switch (operation) {
  case 0:
    return execve((char *)pages + 4096, valid, NULL);
  case 1:
    return execve(executable, (char **)(pages + 4096), NULL);
  case 2:
    return execve(executable, valid, (char **)(pages + 4096));
  case 3:
    return execve(executable, bad_text, NULL);
  case 4:
    return execve(executable, valid, bad_text);
  case 5:
    return execve(executable, (char **)(pages + 4096 - 4), NULL);
  case 6:
    return execve(executable, boundary_text, NULL);
  case 7:
    return execve(executable, valid, boundary_text);
  case 8:
    return execve((char *)pages + 4096 - 16, valid, NULL);
  case 9:
    return execve(executable, too_many, NULL);
  case 10:
    return execve(executable, large, NULL);
  case 11:
    return execve(executable, valid, large);
  default:
    return execve("/system/services/missing-exec-inputs", empty, NULL);
  }
}
static int expected_error(void) {
  return operation < 9 ? EFAULT : operation < 12 ? E2BIG : ENOENT;
}
static void fault(int signal) {
  if (signal != SIGSEGV || invalid_exec() != -1 || errno != expected_error())
    _exit(93);
  siglongjmp(jump, 37);
}
int main(int argc, char **argv) {
  if (argc == 3) {
    CHECK(strcmp(argv[0], "exec-inputs") == 0 && argv[1][0] == 0 &&
          (unsigned char)argv[2][0] == 0xff && argv[2][1] == 0);
    CHECK(getenv("EXEC_INPUTS") && strcmp(getenv("EXEC_INPUTS"), "owned") == 0);
    puts("exec-inputs: PASS 13 invalid/oversized/missing cases including "
         "active handlers, stable FD references and successful empty/non-UTF8 "
         "argument/environment image replacement");
    return 0;
  }
  memset(too_large, 'a', 4096);
  too_large[4096] = 0;
  for (unsigned index = 0; index < 256; ++index)
    too_many[index] = "a";
  pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
               -1, 0);
  CHECK(pages != MAP_FAILED);
  memset(pages + 4096 - 16, 'x', 16);
  CHECK(mprotect(pages + 4096, 4096, PROT_NONE) == 0);
  struct sigaction action = {0};
  action.sa_handler = fault;
  CHECK(sigemptyset(&action.sa_mask) == 0 &&
        sigaction(SIGSEGV, &action, NULL) == 0);
  int64_t baseline = handles();
  for (operation = 0; operation < 13; ++operation) {
    CHECK(invalid_exec() == -1 && errno == expected_error());
    int jumped = sigsetjmp(jump, 1);
    if (!jumped) {
      *(volatile char *)(pages + 4096) = 1;
      CHECK(0);
    }
    CHECK(jumped == 37 && handles() == baseline);
  }
  CHECK(munmap(pages, 8192) == 0);
  char raw[] = {(char)0xff, 0};
  char *arguments[] = {"exec-inputs", "", raw, NULL};
  char *environment[] = {"EXEC_INPUTS=owned", NULL};
  execve(executable, arguments, environment);
  CHECK(0);
}
