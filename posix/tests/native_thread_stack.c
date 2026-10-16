/* Native VM enforcement of user-space pthread stack guard policy. */
#define main directory_baseline_main
#include "native_directory_io.c"
#undef main
#include <pthread.h>
#include <sys/mman.h>

enum { PAGE = 4096, STACK = 32768 };
static uint64_t native6(uint64_t number, uint64_t a, uint64_t b, uint64_t c,
                        uint64_t d, uint64_t e, uint64_t f) {
  register uint64_t r10 __asm__("r10") = d;
  register uint64_t r8 __asm__("r8") = e;
  register uint64_t r9 __asm__("r9") = f;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return number;
}
static int readable(uintptr_t address) {
  char byte;
  return native6(699, (uintptr_t)&byte, address, 1, 0, 0, 0) == 1;
}
static void *owned_stack(void *argument) {
  (void)argument;
  uintptr_t sp;
  __asm__ volatile("mov %%rsp,%0" : "=r"(sp));
  uintptr_t page = sp & ~(uintptr_t)(PAGE - 1);
  unsigned count = 0;
  while (count < STACK / PAGE + 1 && readable(page)) {
    page -= PAGE;
    ++count;
  }
  if (count != STACK / PAGE) {
    fprintf(stderr, "thread-stack: usable pages=%u sp=%lx boundary=%lx\n",
            count, (unsigned long)sp, (unsigned long)page);
    return NULL;
  }
  /* EXACT without REPLACE must fail: the inaccessible guard is reserved. */
  int64_t result = (int64_t)native6(582, page, PAGE, 3, 1, 0, 0);
  /* The current native EXACT mechanism reports occupied ranges as EINVAL. */
  if (result != -22) {
    fprintf(stderr, "thread-stack: exact collision=%ld guard=%lx\n",
            (long)result, (unsigned long)page);
    if (result >= 0)
      native6(583, (uint64_t)result, PAGE, 0, 0, 0, 0);
    return NULL;
  }
  return (void *)page;
}
static void *caller_stack(void *argument) {
  return readable((uintptr_t)argument) ? argument : NULL;
}
int main(void) {
  pthread_attr_t attr;
  CHECK(pthread_attr_init(&attr) == 0);
  CHECK(pthread_attr_setstacksize(&attr, STACK) == 0);
  for (unsigned pass = 0; pass < 16; ++pass) {
    pthread_t thread;
    void *guard = NULL;
    CHECK(pthread_create(&thread, &attr, owned_stack, NULL) == 0);
    CHECK(pthread_join(thread, &guard) == 0 && guard != NULL);
    /* Join must release both usable stack and guard, not just the RW suffix. */
    CHECK(native6(582, (uintptr_t)guard, STACK + PAGE, 3, 1, 0, 0) ==
          (uintptr_t)guard);
    CHECK(native6(583, (uintptr_t)guard, STACK + PAGE, 0, 0, 0, 0) == 0);
  }
  void *stack = mmap(NULL, STACK, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(stack != MAP_FAILED);
  CHECK(pthread_attr_setstack(&attr, stack, STACK) == 0);
  pthread_t thread;
  void *returned = NULL;
  CHECK(pthread_create(&thread, &attr, caller_stack, stack) == 0);
  CHECK(pthread_join(thread, &returned) == 0 && returned == stack);
  CHECK(readable((uintptr_t)stack));
  CHECK(munmap(stack, STACK) == 0);
  CHECK(pthread_attr_destroy(&attr) == 0);
  puts("thread-stack: PASS reserved guard, usable size, join reclamation and "
       "caller ownership");
  return 0;
}
