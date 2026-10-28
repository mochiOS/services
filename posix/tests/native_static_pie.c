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
#ifdef MOCHIOS_STARTUP_IDENTITY
static unsigned long decimal(const char *text) {
  unsigned long value = 0;
  if (!*text) return ~0UL;
  for (int i = 0; i < 10; ++i) {
    if (*text < '0' || *text > '9') return ~0UL;
    value = value * 10 + (unsigned long)(*text++ - '0');
    if (!*text) return value;
  }
  return ~0UL;
}
static int prefix(const char *text, const char *name) {
  while (*name) if (*text++ != *name++) return 0;
  return 1;
}
#endif
__attribute__((noreturn)) void _start(void);
__attribute__((noreturn, used)) static void run(unsigned long *stack) {
  unsigned long status = 99, headers = 0, entry = 0, size = 0, count = 0, bias = 0;
  unsigned long argc = *stack++;
  int identity_ok = 1;
#ifdef MOCHIOS_STARTUP_IDENTITY
  unsigned long expected[4] = {0}, observed[5] = {0};
  unsigned int seen = 0;
  int loader_variables = 0, marker = 0;
  if (argc != 5) identity_ok = 0;
  else for (int i = 0; i < 4; ++i) {
    expected[i] = decimal((const char *)stack[i + 1]);
    if (expected[i] == ~0UL) identity_ok = 0;
  }
#endif
  if (argc < 256) {
    stack += argc + 1;
    while (*stack) {
#ifdef MOCHIOS_STARTUP_IDENTITY
      const char *text = (const char *)*stack;
      if (prefix(text, "LD_LIBRARY_PATH=") || prefix(text, "LD_PRELOAD=") || prefix(text, "LD_AUDIT=")) ++loader_variables;
      if (prefix(text, "MOCHIOS_STARTUP_MARKER=preserved")) ++marker;
#endif
      ++stack;
    }
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
#ifdef MOCHIOS_STARTUP_IDENTITY
      int slot = stack[0] >= 11 && stack[0] <= 14 ? (int)stack[0] - 11 : stack[0] == 23 ? 4 : -1;
      if (slot >= 0) {
        if (seen & (1u << slot)) identity_ok = 0;
        seen |= 1u << slot;
        observed[slot] = stack[1];
      }
#endif
    }
  }
#ifdef MOCHIOS_STARTUP_IDENTITY
  int secure = expected[0] != expected[1] || expected[2] != expected[3];
  for (int i = 0; i < 4; ++i) if (observed[i] != expected[i]) identity_ok = 0;
  if (seen != 31 || observed[4] != (unsigned long)secure || marker != 1 || loader_variables != (secure ? 0 : 3)) identity_ok = 0;
#endif
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
      tls_found != 1 || !identity_ok)
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
