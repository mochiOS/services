/* Real static PIE with relative data/function pointers and demand-zero BSS.
   The entry ABI and native exit are used directly; no host libc/Linux ABI. */
#ifdef MOCHIOS_SHARED_SCOPE
extern int shared_function(int);
extern int shared_value;
int root_override = 41;
#define MAX_TEST_BIAS 0x25000000UL
#else
#define MAX_TEST_BIAS 0x24000000UL
#endif
extern unsigned char __ehdr_start[];
/* Metadata for the compiler-generated template; this native entry does not
   stand in for the C runtime's TLS allocator. */
_Alignas(8192) _Thread_local volatile int tls_initial = 17;
_Thread_local volatile int tls_zero;
static volatile unsigned long modular_value =
    (unsigned long)__ehdr_start - 0x40000000UL;
static volatile int value = 31;
static int *volatile value_pointer = (int *)&value;
static volatile unsigned char zeroes[128 * 1024];
static int addition(int number) { return number + 11; }
static int (*volatile function_pointer)(int) = addition;
__attribute__((noreturn)) void _start(void);
__attribute__((noreturn, used)) static void run(unsigned long *stack) {
  unsigned long status = 99, headers = 0, entry = 0, size = 0, count = 0, bias = 0;
  unsigned long argc = *stack++;
  if (argc < 256) {
    stack += argc + 1;
    while (*stack)
      ++stack;
    ++stack;
    for (int i = 0; i < 64 && stack[0]; ++i, stack += 2) {
      if (stack[0] == 3)
        headers = stack[1];
      if (stack[0] == 4)
        size = stack[1];
      if (stack[0] == 5)
        count = stack[1];
      if (stack[0] == 9)
        entry = stack[1];
      if (stack[0] == 0x6d000004UL)
        bias = stack[1];
    }
  }
  unsigned long base = (unsigned long)__ehdr_start;
  unsigned long phoff = *(unsigned long *)(__ehdr_start + 32);
  int tls_found = 0;
  if (headers == base + phoff && size == 56 && count < 64) {
    for (unsigned long i = 0; i < count; ++i) {
      const unsigned long *header = (const unsigned long *)(headers + i * size);
      if ((unsigned int)header[0] == 7 && header[4] >= sizeof(int) &&
          header[5] > header[4] && header[6] == 8192 &&
          *(const volatile int *)(header[2] + bias) == 17)
        ++tls_found;
    }
  }
  if (headers != base + phoff || size != 56 || count == 0 ||
      entry != (unsigned long)_start || __ehdr_start[16] != 3 || bias != base ||
      tls_found != 1)
    status = 98;
  else if (base >= 0x20000000 && base < MAX_TEST_BIAS &&
           modular_value == base - 0x40000000UL &&
           value_pointer == (int *)&value && *value_pointer == 31 &&
           zeroes[sizeof zeroes - 1] == 0 && function_pointer(31) == 42) {
#ifdef MOCHIOS_SHARED_SCOPE
    if (shared_value != 31 || shared_function(2) != 91) {
      status = 97;
      goto finish;
    }
#endif
    zeroes[sizeof zeroes - 1] = 77;
    if (zeroes[sizeof zeroes - 1] == 77)
      status = 42;
  }
#ifdef MOCHIOS_SHARED_SCOPE
finish:
#endif
  unsigned long number = 574;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(status)
                   : "rcx", "r11", "memory");
  __builtin_trap();
}
__attribute__((naked, noreturn)) void _start(void) {
  __asm__ volatile("mov %rsp, %rdi\n\tandq $-16, %rsp\n\tcall run\n\tud2");
}
