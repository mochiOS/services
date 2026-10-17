/* Freestanding initial-process probe: real IPC, no libc or POSIX service. */
#include <stdint.h>

enum { CLOSE = 626, DUPLICATE = 627, CREATE_ENDPOINT = 629,
       SEND = 630, RECEIVE = 631, RECV = 515, WAIT = 590,
       PAIR = 649, DEBUG = 660,
       WRITE = 675, TABLE = 680, READ = 681, YIELD = 579 };
#define INVALID_ARGUMENT INT64_C(-262139)
#define INVALID_ADDRESS INT64_C(-262142)
#define ACCESS_DENIED INT64_C(-262138)
#define RESOURCE_UNAVAILABLE INT64_C(-262141)
#define PEER_CLOSED INT64_C(-262134)
#define NOT_READY INT64_C(-262137)
struct item { uint32_t handle, reserved; uint64_t rights; };
struct attachments { uint32_t count, flags; struct item items[4]; };
_Static_assert(sizeof(struct attachments) == 72, "IPC attachment ABI");
static uint32_t fillers[4096];
static uint64_t receive_endpoint;

static int64_t native(uint64_t number, uint64_t a, uint64_t b, uint64_t c,
                      uint64_t d) {
  register uint64_t r10 __asm__("r10") = d;
  __asm__ volatile("syscall" : "+a"(number)
                   : "D"(a), "S"(b), "d"(c), "r"(r10)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
static void text(const char *s) {
  uint64_t length = 0;
  while (s[length]) ++length;
  native(DEBUG, (uintptr_t)s, length, 0, 0);
}
static void hex(uint64_t value) {
  char out[] = "0x0000000000000000\n";
  const char digits[] = "0123456789abcdef";
  for (unsigned i = 0; i < 16; ++i) out[17-i] = digits[(value >> (4*i)) & 15];
  native(DEBUG, (uintptr_t)out, sizeof(out)-1, 0, 0);
}
__attribute__((noreturn)) static void fail(unsigned line, int64_t result) {
  text("ipc-handles-initial: FAIL line="); hex(line); hex((uint64_t)result);
  for (;;) native(YIELD, 0, 0, 0, 0);
}
#define CHECK(expression, expected) do { \
  int64_t result = (expression); \
  if (result != (expected)) fail(__LINE__, result); \
} while (0)
static uint64_t count(void) {
  int64_t result = native(TABLE, 0, 0, 0, 0);
  if (result < 0 || result > 4096) fail(__LINE__, result);
  return (uint64_t)result;
}
static int64_t send(uint64_t endpoint, struct attachments *a) {
  static const char message = 'm';
  return native(SEND, endpoint, (uintptr_t)&message, 1, (uintptr_t)a);
}
static int64_t receive(uint64_t output) {
  char message = 0;
  int64_t result = native(RECEIVE, (uintptr_t)&message, 1, output, receive_endpoint);
  if ((uint32_t)result == 1 && message != 'm') fail(__LINE__, message);
  return result;
}
__attribute__((used, noreturn)) static void probe_main(void) {
  text("ipc-handles-initial: start\n");
  int64_t endpoint = native(CREATE_ENDPOINT, 0, 0, 0, 0);
  if (endpoint <= 0) fail(__LINE__, endpoint);
  struct attachments empty = {0};
  CHECK(receive((uintptr_t)&empty), NOT_READY);
  CHECK(native(RECV, 0, 0, 0, 0), NOT_READY);
  CHECK(native(WAIT, 0, 0, 0, 0), NOT_READY);
  uint32_t pair[2] = {0};
  CHECK(native(PAIR, (uintptr_t)pair, 0, 0, 0), 0);
  uint64_t baseline = count();
  struct attachments a = {0};
  a.count = 1; a.items[0].handle = pair[0]; a.items[0].rights = 1; /* READ */
  for (unsigned flags = 1; flags <= 2; ++flags) {
    a.flags = flags; CHECK(send((uint64_t)endpoint, &a), INVALID_ARGUMENT);
  }
  a.flags = 0;
  CHECK(send((uint64_t)endpoint, (struct attachments *)0), INVALID_ADDRESS);
  a.count = 5; CHECK(send((uint64_t)endpoint, &a), INVALID_ARGUMENT);
  a.count = 1; a.items[0].reserved = 1;
  CHECK(send((uint64_t)endpoint, &a), INVALID_ARGUMENT);
  a.items[0].reserved = 0; a.items[0].rights = UINT64_C(1) << 61;
  CHECK(send((uint64_t)endpoint, &a), INVALID_ARGUMENT);
  a.items[0].rights = 1; CHECK(send((uint64_t)endpoint, &a), 0);
  struct attachments received = {0};
  int64_t result = receive((uintptr_t)&received);
  if ((uint32_t)result != 1 || received.count != 1 || received.flags != 2 ||
      received.items[0].rights != 1 || received.items[0].reserved)
    fail(__LINE__, result);
  uint32_t limited = received.items[0].handle;
  if (limited == pair[0] || count() != baseline + 1) fail(__LINE__, limited);
  /* The first receive above was nonblocking. Exercise the blocking entry
     point for subsequent copy-failure and table-exhaustion rollback checks. */
  receive_endpoint = (uint64_t)endpoint;
  static const char byte = 'w';
  CHECK(native(WRITE, limited, (uintptr_t)&byte, 1, 0), ACCESS_DENIED);
  a.items[0].handle = limited; CHECK(send((uint64_t)endpoint, &a), ACCESS_DENIED);
  a.count = 2; a.items[0].handle = pair[0];
  a.items[1].handle = limited; a.items[1].rights = 1;
  CHECK(send((uint64_t)endpoint, &a), ACCESS_DENIED);
  if (count() != baseline + 1) fail(__LINE__, -1);
  a.count = 1; CHECK(send((uint64_t)endpoint, &a), 0);
  CHECK(receive(1), INVALID_ADDRESS); /* Install, copy fault, rollback. */
  if (count() != baseline + 1) fail(__LINE__, -2);
  CHECK(native(WRITE, pair[1], (uintptr_t)&byte, 1, 0), 1);
  char output = 0;
  CHECK(native(READ, limited, (uintptr_t)&output, 1, 0), 1);
  if (output != byte) fail(__LINE__, output);
  CHECK(native(CLOSE, limited, 0, 0, 0), 0);
  if (count() != baseline) fail(__LINE__, -3);
  /* Leave exactly one free slot: receiving two attachments must roll back
     the first insertion when the second cannot be admitted. */
  unsigned fill_count = 0;
  while (count() < 4095) {
    result = native(DUPLICATE, pair[0], 1, 0, 0);
    if (result <= 0 || fill_count >= 4096) fail(__LINE__, result);
    fillers[fill_count++] = (uint32_t)result;
  }
  a.count = 2; a.items[1].handle = pair[0]; a.items[1].rights = 1;
  CHECK(send((uint64_t)endpoint, &a), 0);
  CHECK(receive((uintptr_t)&received), RESOURCE_UNAVAILABLE);
  if (count() != 4095) fail(__LINE__, -4);
  for (unsigned i = 0; i < fill_count; ++i)
    CHECK(native(CLOSE, fillers[i], 0, 0, 0), 0);
  if (count() != baseline) fail(__LINE__, -5);
  CHECK(native(CLOSE, pair[0], 0, 0, 0), 0);
  /* Leaked incoming references would incorrectly keep the read peer alive. */
  CHECK(native(WRITE, pair[1], (uintptr_t)&byte, 1, 0), PEER_CLOSED);
  CHECK(native(CLOSE, pair[1], 0, 0, 0), 0);
  CHECK(native(CLOSE, (uint64_t)endpoint, 0, 0, 0), 0);
  text("ipc-handles-initial: PASS native empty status, nonblocking/blocking receive, native decode errors, attenuation, copy rollback, table exhaustion and reference lifetime\n");
  for (;;) native(YIELD, 0, 0, 0, 0);
}
__attribute__((naked, noreturn, section(".text._start"))) void _start(void) {
  __asm__ volatile("andq $-16, %rsp\n\tcall probe_main\n\tud2");
}
