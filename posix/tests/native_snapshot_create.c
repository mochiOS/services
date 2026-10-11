/* Isolated KVM fixture installed at compositor.service, never production code.
 * Uses the existing capability-service authorization path under test. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum {
  SLEEP = 517,
  FIND_PROCESS = 518,
  IPC_CALL = 588,
  EXIT = 574,
  CLOSE = 626,
  DUP = 627,
  VALUE_GET = 639,
  STATUS = 642,
  WAIT = 643,
  RESUME = 645,
  CREATE = 676,
  SPACE_CLONE = 679
};
static int64_t call6(uint64_t n, uint64_t a, uint64_t b, uint64_t c, uint64_t d,
                     uint64_t e, uint64_t f) {
  register uint64_t r10 __asm__("r10") = d;
  register uint64_t r8 __asm__("r8") = e;
  register uint64_t r9 __asm__("r9") = f;
  __asm__ volatile("syscall"
                   : "+a"(n)
                   : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return (int64_t)n;
}
#define N(n, a, b, c)                                                          \
  call6(n, (uint64_t)(a), (uint64_t)(b), (uint64_t)(c), 0, 0, 0)
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "snapshot-create: FAIL line %d\n", __LINE__);            \
      return 1;                                                                \
    }                                                                          \
  } while (0)
struct status {
  uint64_t pid;
  uint32_t state, reserved;
  uint64_t code;
};
struct context {
  uint64_t entry, stack, argument, tls, flags, reserved[3];
  uint64_t registers[14];
};
_Static_assert(sizeof(struct context) == 176, "native initial context");
static unsigned char stack[65536] __attribute__((aligned(16)));
static volatile uint64_t private_value = 0x11;
static volatile uint64_t initial_rax;
static uint64_t tls_word = UINT64_C(0xabcdef0123456789);
static const char path[] = "/system/services/compositor.service";
static const char label[] = "snapshot-child";

__attribute__((used, noreturn)) static void child(void) {
  uint64_t tls = 0, value = 0;
  __asm__ volatile("movq %%fs:0,%0" : "=r"(tls));
  int ok = private_value == 0x11 &&
           initial_rax == UINT64_C(0x87654321abcdef00) && tls == tls_word &&
           N(VALUE_GET, UINT64_C(0x1234), &value, 0) == 0 && value == 42;
  N(EXIT, ok ? 37 : 99, 0, 0);
  for (;;)
    __asm__ volatile("pause");
}
__attribute__((naked)) static void entry(void) {
  __asm__ volatile("movq %rax,initial_rax(%rip)\n\tcall child\n\tud2");
}
static void put32(void *p, uint32_t v) { memcpy(p, &v, 4); }
static void put64(void *p, uint64_t v) { memcpy(p, &v, 8); }
static size_t metadata(unsigned char *bytes, struct context context) {
  size_t identity = sizeof(path) - 1, name = sizeof(label) - 1;
  size_t start = 32 + identity + name;
  memset(bytes, 0, 512);
  memcpy(bytes, "MCRT", 4);
  bytes[4] = 2;
  bytes[6] = 32;
  put32(bytes + 8, (uint32_t)identity);
  put32(bytes + 12, 176);
  put32(bytes + 20, 1);
  put32(bytes + 24, (uint32_t)name);
  put32(bytes + 28, 1);
  memcpy(bytes + 32, path, identity);
  memcpy(bytes + 32 + identity, label, name);
  memcpy(bytes + start, &context, sizeof(context));
  put64(bytes + start + 176, UINT64_C(0x1234));
  put64(bytes + start + 184, 42);
  return start + 192;
}
static int authorize(uint64_t endpoint) {
  unsigned char request[12 + sizeof(path) - 1] = {0}, reply[2048] = {0};
  put32(request, 0x43414553);
  put64(request + 4, 2);
  memcpy(request + 12, path, sizeof(path) - 1);
  int64_t result = call6(IPC_CALL, endpoint, (uint64_t)request, sizeof(request),
                         (uint64_t)reply, sizeof(reply), 0);
  uint64_t error = 1;
  memcpy(&error, reply, 8);
  if (result < 16 || error)
    fprintf(stderr, "snapshot-create: auth result %lld error %llu\n",
            (long long)result, (unsigned long long)error);
  return result >= 16 && error == 0;
}
int main(void) {
  fprintf(stderr, "snapshot-create: start\n");
  int64_t authority =
      N(FIND_PROCESS, "capability.service", strlen("capability.service"), 0);
  CHECK(authority > 0);
  /* Touch every stack page before capture so initial entry has resident VM. */
  for (size_t i = 0; i < sizeof(stack); i += 4096)
    stack[i] = 1;
  struct context context = {0};
  context.entry = (uint64_t)entry;
  context.stack = (uint64_t)(stack + sizeof(stack));
  context.tls = (uint64_t)&tls_word;
  context.registers[0] = UINT64_C(0x87654321abcdef00);
  unsigned char bytes[512];
  int64_t image = N(SPACE_CLONE, 0, 0, 0);
  CHECK(image > 0);
  int64_t alias = N(DUP, image, UINT64_C(1) << 8, 0);
  CHECK(alias > 0);
  int64_t reduced = N(DUP, image, 0, 0);
  CHECK(reduced > 0);
  size_t length = metadata(bytes, context);
  CHECK(authorize((uint64_t)authority));
  CHECK(N(CREATE, reduced, bytes, length) == -EACCES);
  CHECK(N(CLOSE, reduced, 0, 0) == 0);
  for (unsigned invalid = 0; invalid < 4; invalid++) {
    struct context bad = context;
    if (invalid == 0)
      bad.entry = UINT64_C(0xffff800000001000);
    if (invalid == 1)
      bad.entry = (uint64_t)stack;
    if (invalid == 2)
      bad.stack = (uint64_t)entry + 16;
    if (invalid == 3)
      bad.tls = UINT64_C(0xffff800000001000);
    length = metadata(bytes, bad);
    CHECK(authorize((uint64_t)authority));
    CHECK(N(CREATE, image, bytes, length) == -EFAULT);
  }
  length = metadata(bytes, context);
  CHECK(authorize((uint64_t)authority));
  int64_t process = N(CREATE, image, bytes, length);
  fprintf(stderr, "snapshot-create: result %lld\n", (long long)process);
  CHECK(process > 0);
  CHECK(N(CREATE, image, bytes, length) == -EACCES);
  /* Reauthorization cannot revive an already consumed image through aliases. */
  CHECK(authorize((uint64_t)authority));
  CHECK(N(CREATE, alias, bytes, length) == -EAGAIN);
  CHECK(N(CLOSE, image, 0, 0) == 0 && N(CLOSE, alias, 0, 0) == 0);
  struct status state = {0};
  CHECK(N(STATUS, process, &state, 0) == 0 && state.state == 1);
  CHECK(N(SLEEP, 100, 0, 0) == 0);
  CHECK(N(STATUS, process, &state, 0) == 0 && state.state == 1);
  private_value = 0x22;
  CHECK(N(RESUME, process, 0, 0) == 0);
  for (unsigned i = 0; i < 500; i++) {
    CHECK(N(STATUS, process, &state, 0) == 0);
    if (state.state == 2)
      break;
    CHECK(N(SLEEP, 10, 0, 0) == 0);
  }
  fprintf(stderr, "snapshot-create: exit %llu\n",
          (unsigned long long)state.code);
  CHECK(state.state == 2 && state.code == 37 && private_value == 0x22);
  CHECK(N(WAIT, process, 0, &state) == 0 && state.code == 37);
  CHECK(N(CLOSE, process, 0, 0) == 0);
  fprintf(stderr, "snapshot-create: PASS control attenuation, target "
                  "validation, alias one-shot, stopped creation, COW, RAX, "
                  "TLS, opaque value, retained exit\n");
  return 0;
}
