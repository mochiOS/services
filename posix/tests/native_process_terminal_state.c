/* Isolated KVM probe installed as compositor.service. Child creation still
 * uses the existing execution authority; no extra capabilities are granted. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int64_t native6(uint64_t number, uint64_t a, uint64_t b, uint64_t c,
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
#define N(n, a, b, c)                                                          \
  native6(n, (uint64_t)(a), (uint64_t)(b), (uint64_t)(c), 0, 0, 0)
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "terminal-state: FAIL line=%d: %s\n", __LINE__, #x);     \
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
static unsigned char stack[65536] __attribute__((aligned(16)));
static const char path[] = "/system/services/compositor.service";
static const char label[] = "terminal-child";
static void put32(void *p, uint32_t value) { memcpy(p, &value, 4); }
__attribute__((used, noreturn)) static void child(uint64_t code) {
  N(574, code, 0, 0);
  __builtin_unreachable();
}
__attribute__((naked)) static void entry(void) {
  __asm__ volatile("call child\n\tud2");
}
static int authorize(uint64_t authority) {
  unsigned char request[12 + sizeof(path) - 1] = {0}, reply[2048] = {0};
  put32(request, 0x43414553);
  uint64_t kind = 2, error = 1;
  memcpy(request + 4, &kind, 8);
  memcpy(request + 12, path, sizeof(path) - 1);
  int64_t result = native6(588, authority, (uint64_t)request, sizeof(request),
                           (uint64_t)reply, sizeof(reply), 0);
  memcpy(&error, reply, 8);
  return result >= 16 && error == 0;
}
static int64_t create(uint64_t authority, uint64_t code) {
  unsigned char metadata[512] = {0};
  struct context context = {0};
  context.entry = (uint64_t)entry;
  context.stack = (uint64_t)(stack + sizeof(stack));
  context.argument = code;
  size_t offset = 32 + sizeof(path) - 1 + sizeof(label) - 1;
  memcpy(metadata, "MCRT", 4);
  metadata[4] = 2;
  metadata[6] = 32;
  put32(metadata + 8, sizeof(path) - 1);
  put32(metadata + 12, sizeof(context));
  put32(metadata + 24, sizeof(label) - 1);
  put32(metadata + 28, 1);
  memcpy(metadata + 32, path, sizeof(path) - 1);
  memcpy(metadata + 32 + sizeof(path) - 1, label, sizeof(label) - 1);
  memcpy(metadata + offset, &context, sizeof(context));
  int64_t image = N(679, 0, 0, 0);
  if (image < 0)
    return image;
  int64_t handle = authorize(authority)
                       ? N(676, image, metadata, offset + sizeof(context))
                       : -EACCES;
  if (N(626, image, 0, 0))
    return -EIO;
  return handle;
}
int main(void) {
  _Static_assert(sizeof(struct context) == 176, "native creation context");
  _Static_assert(sizeof(struct status) == 24, "native retained status");
  fprintf(stderr, "terminal-state: start\n");
  int64_t authority =
      N(518, "capability.service", strlen("capability.service"), 0);
  CHECK(authority > 0);
  for (size_t page = 0; page < sizeof(stack); page += 4096)
    stack[page] = 1;
  /* Deterministic natural and forced winners, plus unsynchronized races. */
  unsigned forced = 0, natural = 0;
  for (unsigned attempt = 0; attempt < 20; ++attempt) {
    uint64_t code = attempt == 0 ? 0 : 37;
    int64_t handle = create((uint64_t)authority, code);
    CHECK(handle > 0);
    struct status status = {0};
    uint64_t expected;
    if (attempt < 2) {
      CHECK(N(645, handle, 0, 0) == 0);
      CHECK(N(643, handle, UINT64_MAX, &status) == 0);
      expected = code;
      ++natural;
    } else {
      if (attempt > 2)
        CHECK(N(645, handle, 0, 0) == 0);
      int64_t result = N(646, handle, UINT64_MAX, 0);
      CHECK(result == 0 || result == -ESRCH);
      expected = result == 0 ? UINT64_MAX : code;
      forced += result == 0;
      natural += result == -ESRCH;
      CHECK(N(643, handle, UINT64_MAX, &status) == 0);
    }
    CHECK(status.state == 2 && status.reserved == 0 && status.code == expected);
    /* Retain the handle across reclamation and attempt to replace its code. */
    CHECK(N(517, 2, 0, 0) == 0);
    CHECK(N(646, handle, 123, 0) == -ESRCH);
    CHECK(N(642, handle, &status, 0) == 0);
    CHECK(status.state == 2 && status.code == expected);
    CHECK(N(626, handle, 0, 0) == 0);
  }
  CHECK(forced > 0 && natural >= 2);
  fprintf(stderr,
          "terminal-state: PASS 20 trials, natural=%u forced=%u, zero "
          "and full-width codes, races, retained handles\n",
          natural, forced);
  return 0;
}
