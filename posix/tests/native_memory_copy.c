/* Native own-address-space transfer: no POSIX state enters the kernel. */
#define main directory_baseline_main
#include "native_directory_io.c"
#undef main
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>

enum { MEMORY_COPY = 699, COPY_LIMIT = 4096 };
#define NATIVE_LIMIT_EXCEEDED INT64_C(-262143)
static int64_t copy_memory(void *destination, const void *source,
                           uint64_t length) {
  uint64_t result = MEMORY_COPY;
  __asm__ volatile("syscall"
                   : "+a"(result)
                   : "D"(destination), "S"(source), "d"(length)
                   : "rcx", "r11", "memory");
  return (int64_t)result;
}
static sigjmp_buf jump_target;
static void *inaccessible;
static volatile sig_atomic_t caught;
static void handler(int signal) {
  char output[16];
  if (signal != SIGSEGV || copy_memory(output, inaccessible, 1) != -EFAULT ||
      copy_memory(output, "nested", 7) != 7 || strcmp(output, "nested"))
    _exit(91);
  caught = 1;
  siglongjmp(jump_target, 37);
}
int main(void) {
  unsigned char *pages = mmap(NULL, COPY_LIMIT * 3, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(pages != MAP_FAILED);
  inaccessible = pages + COPY_LIMIT * 2;
  CHECK(mprotect(inaccessible, COPY_LIMIT, PROT_NONE) == 0);
  CHECK(copy_memory(NULL, NULL, 0) == 0);
  CHECK(copy_memory(pages, pages, COPY_LIMIT + 1) == NATIVE_LIMIT_EXCEEDED);
  CHECK(copy_memory(NULL, NULL, UINT64_MAX) == NATIVE_LIMIT_EXCEEDED);
  for (unsigned index = 0; index < COPY_LIMIT; ++index)
    pages[index] = index;
  CHECK(copy_memory(pages + COPY_LIMIT, pages, COPY_LIMIT) == COPY_LIMIT);
  CHECK(memcmp(pages, pages + COPY_LIMIT, COPY_LIMIT) == 0);
  CHECK(copy_memory(pages + 1, pages, 64) == 64);
  for (unsigned index = 0; index < 64; ++index)
    CHECK(pages[index + 1] == (unsigned char)index);
  for (unsigned round = 0; round < 16; ++round) {
    CHECK(copy_memory(pages, inaccessible, 1) == -EFAULT);
    CHECK(copy_memory(inaccessible, pages, 1) == -EFAULT);
    CHECK(copy_memory(pages, NULL, 1) == -EFAULT);
    CHECK(copy_memory(pages, (void *)UINTPTR_MAX, 1) == -EFAULT);
  }
  CHECK(mprotect(pages + COPY_LIMIT, COPY_LIMIT, PROT_READ) == 0);
  CHECK(copy_memory(pages + COPY_LIMIT, pages, 1) == -EFAULT);
  strcpy((char *)pages, "parent");
  pid_t child = fork();
  CHECK(child >= 0);
  if (!child)
    _exit(copy_memory(pages, "child", 6) == 6 && !strcmp((char *)pages, "child")
              ? 0
              : 92);
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  CHECK(strcmp((char *)pages, "parent") == 0);
  struct sigaction action = {0};
  action.sa_handler = handler;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  int64_t baseline = native_count();
  for (unsigned round = 0; round < 16; ++round) {
    caught = 0;
    int jumped = sigsetjmp(jump_target, 1);
    if (!jumped) {
      (void)*(volatile unsigned char *)inaccessible;
      CHECK(0);
    }
    CHECK(jumped == 37 && caught && native_count() == baseline);
  }
  CHECK(munmap(pages, COPY_LIMIT * 3) == 0);
  puts("memory-copy: PASS bounded snapshots, overlap, protection, invalid "
       "pointers, COW and copy inside 16 active exception handlers");
  return 0;
}
