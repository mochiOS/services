/* Bare native integration: real worker, provider IPC and completion Handles. */
#include <stdatomic.h>
#include <stdint.h>
enum {
  CREATE = 577,
  YIELD = 579,
  MAP = 582,
  UNMAP = 583,
  SYNC = 586,
  CLOSE = 626,
  DUPLICATE = 627,
  ENDPOINT = 629,
  RECEIVE = 631,
  REPLY = 633,
  PROVIDER = 637,
  WAIT = 647,
  DEBUG = 660,
  READ = 673,
  WRITE = 674
};
struct attachments {
  uint32_t count, flags;
  struct {
    uint32_t handle, reserved;
    uint64_t rights;
  } items[4];
};
struct context {
  uint64_t entry, stack, argument, tls, flags, reserved[3], registers[14];
};
struct wait_item {
  uint32_t handle, minimum;
  uint64_t interests, observed;
};
_Static_assert(sizeof(struct context) == 176, "ThreadCreateContext");
_Static_assert(sizeof(struct wait_item) == 24, "HandleWaitItem");
static _Alignas(16) unsigned char stack[32768];
static _Atomic uint64_t backing;
static _Atomic unsigned allow_sync, entered, syncs, writes, failed;
void *memset(void *target, int byte, __SIZE_TYPE__ length) {
  volatile unsigned char *p = target;
  while (length--)
    *p++ = (unsigned char)byte;
  return target;
}
static int64_t native(uint64_t n, uint64_t a, uint64_t b, uint64_t c,
                      uint64_t d, uint64_t e, uint64_t f) {
  register uint64_t r10 __asm__("r10") = d, r8 __asm__("r8") = e,
                        r9 __asm__("r9") = f;
  __asm__ volatile("syscall"
                   : "+a"(n)
                   : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return (int64_t)n;
}
static void text(const char *s) {
  uint64_t n = 0;
  while (s[n])
    ++n;
  native(DEBUG, (uintptr_t)s, n, 0, 0, 0, 0);
}
__attribute__((noreturn)) static void fail(unsigned line, int64_t value) {
  const char hex[] = "0123456789abcdef";
  char s[] = "native-async-writeback: FAIL line=0000 result=0000000000000000\n";
  for (unsigned i = 0; i < 4; ++i)
    s[sizeof("native-async-writeback: FAIL line=") + 2 - i] =
        hex[(line >> (4 * i)) & 15];
  for (unsigned i = 0; i < 16; ++i)
    s[sizeof(s) - 3 - i] = hex[((uint64_t)value >> (4 * i)) & 15];
  text(s);
  for (;;)
    native(YIELD, 0, 0, 0, 0, 0, 0);
}
#define CHECK(e, v)                                                            \
  do {                                                                         \
    int64_t r = (int64_t)(e);                                                  \
    if (r != (int64_t)(v))                                                     \
      fail(__LINE__, r);                                                       \
  } while (0)
static uint64_t get64(const unsigned char *p) {
  uint64_t v = 0;
  for (unsigned i = 0; i < 8; ++i)
    v |= (uint64_t)p[i] << (8 * i);
  return v;
}
static void put64(unsigned char *p, uint64_t v) {
  for (unsigned i = 0; i < 8; ++i)
    p[i] = (unsigned char)(v >> (8 * i));
}
__attribute__((noreturn)) static void provider(void) {
  int64_t endpoint = native(ENDPOINT, 0, 0, 0, 0, 0, 0);
  if (endpoint <= 0)
    fail(__LINE__, endpoint);
  int64_t object = native(PROVIDER, endpoint, 101, 1 | 2 | 64, 0, 0, 0);
  if (object <= 0)
    fail(__LINE__, object);
  atomic_store_explicit(&backing, object, memory_order_release);
  for (;;) {
    unsigned char request[48 + 4096], response[40 + 4096] = {0};
    struct attachments in = {0}, out = {0};
    int64_t received = native(RECEIVE, (uintptr_t)request, sizeof(request),
                              (uintptr_t)&in, endpoint, 0, 0);
    if (received < 0 || in.count || in.flags != 1 || get64(request + 8) != 101)
      fail(__LINE__, received);
    unsigned opcode = request[6] | (unsigned)request[7] << 8;
    if (opcode == 4)
      continue;
    for (unsigned i = 0; i < 8; ++i)
      response[i] = request[i];
    put64(response + 16, 101);
    unsigned length = 40;
    if (opcode == 9)
      put64(response + 24, 77);
    else if (opcode == 6) {
      CHECK(get64(request + 24), 0);
      CHECK((uint32_t)get64(request + 32), 4096);
      put64(response + 24, 4096);
      response[33] = 16;
      for (unsigned i = 0; i < 4096; ++i)
        response[40 + i] = 'a';
      length += 4096;
    } else if (opcode == 7) {
      CHECK(get64(request + 24), 0);
      CHECK((uint32_t)get64(request + 32), 4096);
      if (request[48] != 'Q' && request[48] != 'R')
        fail(__LINE__, request[48]);
      atomic_fetch_add_explicit(&writes, 1, memory_order_release);
      put64(response + 24, 4096);
    } else if (opcode == 8) {
      atomic_store_explicit(&entered, 1, memory_order_release);
      while (!atomic_load_explicit(&allow_sync, memory_order_acquire))
        native(YIELD, 0, 0, 0, 0, 0, 0);
      if (atomic_load_explicit(&failed, memory_order_acquire))
        put64(response + 8, (uint64_t)INT64_C(-5));
      atomic_fetch_add_explicit(&syncs, 1, memory_order_release);
    } else
      fail(__LINE__, opcode);
    CHECK(native(REPLY, (uint64_t)received >> 32, (uintptr_t)response, length,
                 (uintptr_t)&out, 0, 0),
          0);
  }
}
static int64_t submit(uint64_t address) {
  int64_t result = native(SYNC, address, 4096, 1, 0, 0, 0);
  if (result <= 0)
    fail(__LINE__, result);
  return result;
}
static void wait_result(uint64_t handle, uint64_t phase, uint64_t error) {
  struct wait_item item = {.handle = handle, .interests = 2};
  CHECK(native(WAIT, (uintptr_t)&item, 1, UINT64_MAX, 0, 0, 0), 0);
  CHECK(item.observed, 2);
  unsigned char record[16];
  CHECK(native(READ, handle, (uintptr_t)record, 16, 0, 0, 0), 16);
  CHECK(get64(record), phase);
  CHECK(get64(record + 8), error);
}
__attribute__((used, noreturn)) static void probe_main(void) {
  text("native-async-writeback: start\n");
  struct context context = {0};
  context.entry = (uintptr_t)provider;
  context.stack = (uintptr_t)(stack + sizeof(stack) - 8);
  int64_t thread =
      native(CREATE, (uintptr_t)&context, sizeof(context), 0, 0, 0, 0);
  if (thread <= 0)
    fail(__LINE__, thread);
  uint64_t object;
  while (!(object = atomic_load_explicit(&backing, memory_order_acquire)))
    native(YIELD, 0, 0, 0, 0, 0, 0);
  int64_t address = native(MAP, 0, 4096, 3, 2, object, 0);
  if (address <= 0)
    fail(__LINE__, address);
  volatile unsigned char *p = (void *)(uintptr_t)address;
  CHECK(p[0], 'a');
  p[0] = 'Q';
  int64_t completion = submit(address);
  while (!atomic_load_explicit(&entered, memory_order_acquire))
    native(YIELD, 0, 0, 0, 0, 0, 0);
  unsigned char record[16];
  CHECK(native(READ, completion, (uintptr_t)record, 16, 0, 0, 0), 16);
  CHECK(get64(record), 0);
  struct wait_item poll = {.handle = completion, .interests = 2};
  CHECK(native(WAIT, (uintptr_t)&poll, 1, 0, 0, 0, 0), INT64_C(-262137));
  atomic_store_explicit(&allow_sync, 1, memory_order_release);
  wait_result(completion, 1, 0);
  int64_t wait_only = native(DUPLICATE, completion, 16, 0, 0, 0, 0);
  if (wait_only <= 0)
    fail(__LINE__, wait_only);
  CHECK(native(READ, wait_only, (uintptr_t)record, 16, 0, 0, 0),
        INT64_C(-262138));
  CHECK(native(WRITE, completion, (uintptr_t)record, 16, 0, 0, 0),
        INT64_C(-262138));
  CHECK(native(CLOSE, wait_only, 0, 0, 0, 0, 0), 0);
  CHECK(native(CLOSE, completion, 0, 0, 0, 0, 0), 0);
  p[0] = 'R';
  atomic_store_explicit(&failed, 1, memory_order_release);
  completion = submit(address);
  wait_result(completion, 2, (uint64_t)INT64_C(-5));
  CHECK(native(CLOSE, completion, 0, 0, 0, 0, 0), 0);
  atomic_store_explicit(&failed, 0, memory_order_release);
  atomic_store_explicit(&entered, 0, memory_order_release);
  atomic_store_explicit(&allow_sync, 0, memory_order_release);
  completion = submit(address);
  while (!atomic_load_explicit(&entered, memory_order_acquire))
    native(YIELD, 0, 0, 0, 0, 0, 0);
  CHECK(native(CLOSE, completion, 0, 0, 0, 0, 0), 0);
  atomic_store_explicit(&allow_sync, 1, memory_order_release);
  while (atomic_load_explicit(&syncs, memory_order_acquire) < 3)
    native(YIELD, 0, 0, 0, 0, 0, 0);
  CHECK(native(UNMAP, address, 4096, 0, 0, 0, 0), 0);
  CHECK(native(CLOSE, object, 0, 0, 0, 0, 0), 0);
  if (atomic_load_explicit(&writes, memory_order_acquire) < 3)
    fail(__LINE__, atomic_load(&writes));
  text("native-async-writeback: PASS pending, wake, success, opaque failure, "
       "rights, close-before-completion\n");
  for (;;)
    native(YIELD, 0, 0, 0, 0, 0, 0);
}
__attribute__((naked, noreturn, section(".text._start"))) void _start(void) {
  __asm__ volatile("andq $-16,%rsp\n\tcall probe_main\n\tud2");
}
