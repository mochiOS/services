/* Native provider readiness across actual private/shared hardware page faults.
 */
#include <stdatomic.h>
#include <stdint.h>

enum {
  THREAD_CREATE = 577,
  YIELD = 579,
  MEMORY_MAP = 582,
  MEMORY_UNMAP = 583,
  MEMORY_PROTECT = 584,
  HANDLE_CLOSE = 626,
  ENDPOINT_CREATE = 629,
  RECEIVE = 631,
  REPLY = 633,
  PROVIDER_CREATE = 637,
  DEBUG = 660,
  READ_AT = 673
};
struct attachment {
  uint32_t handle, reserved;
  uint64_t rights;
};
struct attachments {
  uint32_t count, flags;
  struct attachment items[4];
};
struct thread_context {
  uint64_t entry, stack, argument, tls, flags, reserved[3], registers[14];
};
_Static_assert(sizeof(struct thread_context) == 176, "ThreadCreateContext ABI");
static _Alignas(16) unsigned char worker_stack[16384];
static _Atomic uint64_t backing;
static _Atomic unsigned reads[2];

/* Compiler-emitted aggregate initialization, without a libc runtime. */
void *memset(void *target, int byte, __SIZE_TYPE__ length) {
  volatile unsigned char *output = target;
  for (__SIZE_TYPE__ i = 0; i < length; ++i)
    output[i] = (unsigned char)byte;
  return target;
}

static int64_t native(uint64_t number, uint64_t a, uint64_t b, uint64_t c,
                      uint64_t d, uint64_t e, uint64_t f) {
  register uint64_t r10 __asm__("r10") = d;
  register uint64_t r8 __asm__("r8") = e;
  register uint64_t r9 __asm__("r9") = f;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
static void text(const char *s) {
  uint64_t length = 0;
  while (s[length])
    ++length;
  native(DEBUG, (uintptr_t)s, length, 0, 0, 0, 0);
}
__attribute__((noreturn)) static void fail(unsigned line, int64_t result) {
  const char digits[] = "0123456789abcdef";
  char message[] =
      "native-fault-initial: FAIL line=0000 result=0000000000000000\n";
  for (unsigned i = 0; i < 4; ++i)
    message[sizeof("native-fault-initial: FAIL line=") + 2 - i] =
        digits[(line >> (4 * i)) & 15];
  for (unsigned i = 0; i < 16; ++i)
    message[sizeof(message) - 3 - i] =
        digits[((uint64_t)result >> (4 * i)) & 15];
  text(message);
  for (;;)
    native(YIELD, 0, 0, 0, 0, 0, 0);
}
#define CHECK(expression, expected)                                            \
  do {                                                                         \
    int64_t result = (expression);                                             \
    if (result != (expected))                                                  \
      fail(__LINE__, result);                                                  \
  } while (0)
static uint64_t get64(const unsigned char *p) {
  uint64_t value = 0;
  for (unsigned i = 0; i < 8; ++i)
    value |= (uint64_t)p[i] << (8 * i);
  return value;
}
static void put64(unsigned char *p, uint64_t value) {
  for (unsigned i = 0; i < 8; ++i)
    p[i] = (unsigned char)(value >> (8 * i));
}

__attribute__((noreturn)) static void provider(void) {
  int64_t endpoint = native(ENDPOINT_CREATE, 0, 0, 0, 0, 0, 0);
  if (endpoint <= 0)
    fail(__LINE__, endpoint);
  int64_t handle = native(PROVIDER_CREATE, endpoint, 101, 1 | 64, 0, 0, 0);
  if (handle <= 0)
    fail(__LINE__, handle);
  atomic_store_explicit(&backing, handle, memory_order_release);
  for (;;) {
    unsigned char request[48], response[40 + 4096] = {0};
    struct attachments incoming = {0}, outgoing = {0};
    int64_t received = native(RECEIVE, (uintptr_t)request, sizeof(request),
                              (uintptr_t)&incoming, endpoint, 0, 0);
    if (received < 0 || (uint32_t)received != 48 || incoming.count ||
        incoming.flags != 1 || get64(request + 8) != 101)
      fail(__LINE__, received);
    unsigned opcode = request[6] | (unsigned)request[7] << 8;
    if (opcode == 4)
      continue; /* asynchronous reference release */
    for (unsigned i = 0; i < 8; ++i)
      response[i] = request[i];
    put64(response + 16, 101);
    unsigned length = 40;
    if (opcode == 9) {
      put64(response + 24, 77);
    } else if (opcode == 6) {
      uint64_t offset = get64(request + 24);
      if (offset != 0 && offset != 4096)
        fail(__LINE__, offset);
      CHECK((uint32_t)get64(request + 32), 4096);
      unsigned page = (unsigned)(offset / 4096);
      unsigned count =
          atomic_fetch_add_explicit(&reads[page], 1, memory_order_release);
      if (count < 3) {
        put64(response + 8, (uint64_t)INT64_C(-262137)); /* native NotReady */
      } else {
        put64(response + 24, 4096);
        response[33] = 16; /* u32 data_length = 4096 */
        for (unsigned i = 0; i < 4096; ++i)
          response[40 + i] = (unsigned char)('a' + page);
        length += 4096;
      }
    } else
      fail(__LINE__, opcode);
    CHECK(native(REPLY, (uint64_t)received >> 32, (uintptr_t)response, length,
                 (uintptr_t)&outgoing, 0, 0),
          0);
  }
}
__attribute__((used, noreturn)) static void probe_main(void) {
  text("native-fault-initial: start\n");
  struct thread_context context = {0};
  context.entry = (uintptr_t)provider;
  context.stack = (uintptr_t)(worker_stack + sizeof(worker_stack) - 8);
  int64_t thread =
      native(THREAD_CREATE, (uintptr_t)&context, sizeof(context), 0, 0, 0, 0);
  if (thread <= 0)
    fail(__LINE__, thread);
  uint64_t handle;
  while (!(handle = atomic_load_explicit(&backing, memory_order_acquire)))
    native(YIELD, 0, 0, 0, 0, 0, 0);
  int64_t private_address = native(MEMORY_MAP, 0, 4096, 1, 0, handle, 0);
  int64_t shared_address = native(MEMORY_MAP, 0, 4096, 1, 2, handle, 4096);
  if (private_address <= 0)
    fail(__LINE__, private_address);
  if (shared_address <= 0)
    fail(__LINE__, shared_address);
  volatile unsigned char *private_bytes = (void *)(uintptr_t)private_address;
  volatile unsigned char *shared_bytes = (void *)(uintptr_t)shared_address;
  CHECK(private_bytes[0], 'a');
  CHECK(private_bytes[4095], 'a');
  CHECK(shared_bytes[0], 'b');
  CHECK(shared_bytes[4095], 'b');
  CHECK(atomic_load_explicit(&reads[0], memory_order_acquire), 4);
  CHECK(atomic_load_explicit(&reads[1], memory_order_acquire), 4);
  CHECK(native(MEMORY_PROTECT, private_address, 4096, 0, 0, 0, 0), 0);
  CHECK(native(MEMORY_PROTECT, shared_address, 4096, 0, 0, 0, 0), 0);
  CHECK(native(MEMORY_PROTECT, private_address, 4096, 1, 0, 0, 0), 0);
  CHECK(native(MEMORY_PROTECT, shared_address, 4096, 1, 0, 0, 0), 0);
  CHECK(private_bytes[0], 'a');
  CHECK(shared_bytes[0], 'b');
  CHECK(native(MEMORY_UNMAP, private_address, 4096, 0, 0, 0, 0), 0);
  CHECK(native(MEMORY_UNMAP, shared_address, 4096, 0, 0, 0, 0), 0);
  CHECK(native(HANDLE_CLOSE, handle, 0, 0, 0, 0, 0), 0);
  text("native-fault-initial: PASS private/shared hardware faults retry native "
       "NotReady three times, protect and unmap\n");
  for (;;)
    native(YIELD, 0, 0, 0, 0, 0, 0);
}
__attribute__((naked, noreturn, section(".text._start"))) void _start(void) {
  __asm__ volatile("andq $-16, %rsp\n\tcall probe_main\n\tud2");
}
