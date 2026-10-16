/* Isolated initial-process probe. Freestanding: no CRT, libc, POSIX service,
 * installed SDK runtime, or additional capabilities are involved. */
#include <stdint.h>

static int64_t native(uint64_t number, uint64_t a, uint64_t b, uint64_t c,
                      uint64_t d) {
  register uint64_t r10 __asm__("r10") = d;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(a), "S"(b), "d"(c), "r"(r10)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
static void text(const char *value) {
  uint64_t length = 0;
  while (value[length])
    ++length;
  native(660, (uintptr_t)value, length, 0, 0);
}
static void hex(uint64_t value) {
  char bytes[] = "0x0000000000000000\n";
  const char digits[] = "0123456789abcdef";
  for (unsigned i = 0; i < 16; ++i)
    bytes[17 - i] = digits[(value >> (4 * i)) & 15];
  native(660, (uintptr_t)bytes, sizeof(bytes) - 1, 0, 0);
}
__attribute__((noreturn)) static void fail(unsigned line, int64_t result) {
  text("object-wait-initial: FAIL line=");
  hex(line);
  hex((uint64_t)result);
  for (;;)
    native(579, 0, 0, 0, 0);
}
#define CHECK_RESULT(expression, expected)                                     \
  do {                                                                         \
    int64_t result = (expression);                                              \
    if (result != (expected))                                                   \
      fail(__LINE__, result);                                                   \
  } while (0)
#define NOT_READY INT64_C(-262137)
#define INVALID_ARGUMENT INT64_C(-262139)
#define INVALID_ADDRESS INT64_C(-262142)
#define ACCESS_DENIED INT64_C(-262138)

struct wait_item {
  uint32_t handle, minimum;
  uint64_t interests, observed;
};
struct guard {
  uint64_t address, expected;
};
struct instant {
  uint64_t seconds;
  uint32_t nanoseconds, reserved;
};
struct thread_context {
  uint64_t entry, stack, argument, tls, flags, reserved[3], registers[14];
};
static uint64_t now(void) {
  struct instant value = {0};
  CHECK_RESULT(native(640, UINT64_C(0x4d4e55434c4b0002),
                      (uintptr_t)&value, 0, 0), 0);
  return value.seconds * UINT64_C(1000000000) + value.nanoseconds;
}
static uint64_t load(uint64_t *word) {
  return __atomic_load_n(word, __ATOMIC_SEQ_CST);
}
static void store(uint64_t *word, uint64_t value) {
  __atomic_store_n(word, value, __ATOMIC_SEQ_CST);
}
static uint64_t command, epoch, completed, wakes, worker_error;
static unsigned char worker_stack[65536] __attribute__((aligned(16)));
__attribute__((used, noreturn)) static void worker(void) {
  for (uint64_t round = 1; round <= 32; ++round) {
    while (load(&command) != round)
      native(579, 0, 0, 0, 0);
    for (unsigned delay = 0; delay < 64; ++delay)
      native(579, 0, 0, 0, 0);
    store(&epoch, round);
    int64_t result = native(653, (uintptr_t)&epoch, UINT64_MAX, 0, 0);
    if (result < 0 || result > 1)
      store(&worker_error, (uint64_t)result);
    if (result == 1)
      __atomic_fetch_add(&wakes, 1, __ATOMIC_SEQ_CST);
    store(&completed, round);
  }
  native(578, 0, 0, 0, 0);
  __builtin_unreachable();
}
__attribute__((naked, noreturn)) static void worker_entry(void) {
  __asm__ volatile("andq $-16, %rsp\n\tcall worker\n\tud2");
}
__attribute__((used, noreturn)) static void probe_main(void) {
  _Static_assert(sizeof(struct wait_item) == 24, "wait ABI");
  _Static_assert(sizeof(struct thread_context) == 176, "thread ABI");
  text("object-wait-initial: start\n");
  CHECK_RESULT(native(647, 0, 0, 0, 0), NOT_READY);
  CHECK_RESULT(native(647, 0, 65, 0, 0), INVALID_ARGUMENT);
  CHECK_RESULT(native(647, 0, 1, 0, 0), INVALID_ADDRESS);
  CHECK_RESULT(native(682, 0, 0, 0, UINT64_MAX - 7), INVALID_ADDRESS);
  uint64_t start = now();
  CHECK_RESULT(native(647, 0, 0, start + 20000000, 0), NOT_READY);
  if (now() - start < 20000000)
    fail(__LINE__, -1);
  uint32_t pair[2] = {0};
  CHECK_RESULT(native(649, (uintptr_t)pair, 0, 0, 0), 0);
  struct wait_item item = {pair[0], 0, 2, 0};
  CHECK_RESULT(native(647, (uintptr_t)&item, 1, 0, 0), NOT_READY);
  int64_t limited = native(627, pair[0], 1, 0, 0); /* READ without WAIT */
  if (limited <= 0)
    fail(__LINE__, limited);
  item.handle = (uint32_t)limited;
  CHECK_RESULT(native(647, (uintptr_t)&item, 1, 0, 0), ACCESS_DENIED);
  CHECK_RESULT(native(626, (uint64_t)limited, 0, 0, 0), 0);
  item.handle = pair[0];
  const unsigned char byte = 'w';
  CHECK_RESULT(native(675, pair[1], (uintptr_t)&byte, 1, 0), 1);
  CHECK_RESULT(native(647, (uintptr_t)&item, 1, 0, 0), 0);
  if (item.observed != 2)
    fail(__LINE__, (int64_t)item.observed);
  unsigned char received = 0;
  CHECK_RESULT(native(681, pair[0], (uintptr_t)&received, 1, 0), 1);
  if (received != byte)
    fail(__LINE__, received);
  CHECK_RESULT(native(626, pair[1], 0, 0, 0), 0);
  item.interests = 8;
  CHECK_RESULT(native(647, (uintptr_t)&item, 1, 0, 0), 0);
  if (item.observed != 8)
    fail(__LINE__, (int64_t)item.observed);
  CHECK_RESULT(native(626, pair[0], 0, 0, 0), 0);
  CHECK_RESULT(native(647, (uintptr_t)&item, 1, 0, 0), INVALID_ARGUMENT);
  struct thread_context context = {0};
  context.entry = (uintptr_t)worker_entry;
  context.stack = (uintptr_t)(worker_stack + sizeof(worker_stack));
  int64_t thread = native(577, (uintptr_t)&context, sizeof(context), 0, 0);
  if (thread <= 0)
    fail(__LINE__, thread);
  for (uint64_t round = 1; round <= 32; ++round) {
    struct guard guard = {(uintptr_t)&epoch, round - 1};
    store(&command, round);
    CHECK_RESULT(native(682, 0, 0, now() + 2000000000,
                        (uintptr_t)&guard), NOT_READY);
    uint64_t deadline = now() + 2000000000;
    while (load(&completed) != round && now() < deadline)
      native(579, 0, 0, 0, 0);
    if (load(&completed) != round || load(&worker_error))
      fail(__LINE__, (int64_t)load(&worker_error));
    CHECK_RESULT(native(653, (uintptr_t)&epoch, UINT64_MAX, 0, 0), 0);
  }
  if (!load(&wakes))
    fail(__LINE__, -2); /* At least one wait must really have parked. */
  text("object-wait-initial: PASS native errors, deadlines, rights, stream readiness, 32 guarded wakeups\n");
  for (;;)
    native(579, 0, 0, 0, 0);
}
__attribute__((naked, noreturn, section(".text._start"))) void _start(void) {
  __asm__ volatile("andq $-16, %rsp\n\tcall probe_main\n\tud2");
}
