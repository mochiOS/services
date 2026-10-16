#define _GNU_SOURCE
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t child;
static int *bad_status;
static unsigned mode, context;
static sigjmp_buf jump;
#define CHECK(test)                                                            \
  do {                                                                         \
    if (!(test)) {                                                             \
      fprintf(stderr,                                                          \
              "wait-output: FAIL mode=%u context=%u line=%d errno=%d: %s\n",   \
              mode, context, __LINE__, errno, #test);                          \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static int64_t handles(void) {
  uint64_t number = 680;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(0ULL), "S"(0ULL), "d"(0ULL)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
static void fault(int signal) {
  if (signal != SIGSEGV || waitpid(child, bad_status, 0) != -1 ||
      errno != EFAULT)
    _exit(93);
  siglongjmp(jump, 37);
}
int main(void) {
  unsigned char *pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(pages != MAP_FAILED);
  CHECK(mprotect(pages, 4096, PROT_NONE) == 0 &&
        mprotect(pages + 4096, 4096, PROT_READ) == 0);
  struct sigaction action = {0};
  action.sa_handler = fault;
  CHECK(sigemptyset(&action.sa_mask) == 0 &&
        sigaction(SIGSEGV, &action, NULL) == 0);
  int64_t baseline = handles();
  for (mode = 0; mode < 2; ++mode) {
    bad_status = (int *)(pages + mode * 4096);
    for (context = 0; context < 2; ++context) {
      child = fork();
      CHECK(child >= 0);
      if (!child)
        _exit(37);
      if (!context)
        CHECK(waitpid(child, bad_status, 0) == -1 && errno == EFAULT);
      else {
        int jumped = sigsetjmp(jump, 1);
        if (!jumped) {
          *(volatile char *)pages = 1;
          CHECK(0);
        }
        CHECK(jumped == 37);
      }
      int status;
      CHECK(waitpid(child, &status, WNOHANG) == -1 && errno == ECHILD);
      CHECK(handles() == baseline);
    }
  }
  int go[2];
  CHECK(pipe(go) == 0);
  child = fork();
  CHECK(child >= 0);
  if (!child) {
    close(go[1]);
    char byte;
    _exit(read(go[0], &byte, 1) == 1 ? 42 : 92);
  }
  CHECK(close(go[0]) == 0);
  CHECK(waitpid(child, bad_status, WNOHANG) == 0);
  CHECK(write(go[1], "g", 1) == 1 && close(go[1]) == 0);
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 42);
  child = fork();
  CHECK(child >= 0);
  if (!child)
    _exit(21);
  CHECK(waitpid(child, NULL, 0) == child);
  child = fork();
  CHECK(child >= 0);
  if (!child)
    _exit(19);
  unsigned char output[6];
  memset(output, 0xa5, sizeof(output));
  CHECK(waitpid(child, (int *)(output + 1), 0) == child);
  memcpy(&status, output + 1, sizeof(status));
  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 19 && output[0] == 0xa5 &&
        output[5] == 0xa5);
  child = fork();
  CHECK(child >= 0);
  if (!child) {
    for (;;)
      pause();
  }
  CHECK(kill(child, SIGSTOP) == 0);
  CHECK(waitpid(child, bad_status, WUNTRACED) == -1 && errno == EFAULT);
  CHECK(waitpid(child, &status, WUNTRACED | WNOHANG) == 0);
  CHECK(kill(child, SIGCONT) == 0);
  CHECK(waitpid(child, bad_status, WCONTINUED) == -1 && errno == EFAULT);
  CHECK(waitpid(child, &status, WCONTINUED | WNOHANG) == 0);
  CHECK(kill(child, SIGTERM) == 0);
  CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
        WTERMSIG(status) == SIGTERM);
  CHECK(handles() == baseline);
  CHECK(munmap(pages, 8192) == 0);
  puts("wait-output: PASS exit EFAULT including active handlers, consumed "
       "stop/continue events, WNOHANG/NULL no-copy, unaligned status and "
       "stable handles");
  return 0;
}
