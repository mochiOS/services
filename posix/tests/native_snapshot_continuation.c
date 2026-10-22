/* KVM-only probe of the actual posix-client continuation linked from the SDK
 * runtime archive. Installed in the existing isolated Compositor fixture. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct context {
  uint64_t entry, stack, argument, tls, flags, reserved[3], registers[14];
};
struct status {
  uint64_t pid;
  uint32_t state, reserved;
  uint64_t code;
  uint64_t image_revision;
};
extern uint64_t mochios_posix_capture_snapshot(struct context *, uint64_t,
                                               uint64_t (*)(void))
    __attribute__((returns_twice));
static volatile uint64_t private_value = 0x11;
static int64_t native(uint64_t n, uint64_t a, uint64_t b, uint64_t c,
                      uint64_t d, uint64_t e) {
  register uint64_t r10 __asm__("r10") = d;
  register uint64_t r8 __asm__("r8") = e;
  __asm__ volatile("syscall"
                   : "+a"(n)
                   : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8)
                   : "rcx", "r11", "memory");
  return (int64_t)n;
}
#define N(n, a, b, c)                                                          \
  native(n, (uint64_t)(a), (uint64_t)(b), (uint64_t)(c), 0, 0)
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "snapshot-continuation: FAIL line %d\n", __LINE__);      \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static uint64_t capture(void) { return (uint64_t)N(679, 0, 0, 0); }
static uint64_t fail_capture(void) { return (uint64_t)(int64_t)-ENOMEM; }
static void put32(void *p, uint32_t value) { memcpy(p, &value, 4); }
static void put64(void *p, uint64_t value) { memcpy(p, &value, 8); }
static const char path[] = "/system/services/compositor.service";
static const char label[] = "continuation-child";
static int authorize(uint64_t endpoint) {
  unsigned char request[12 + sizeof(path) - 1] = {0}, reply[2048] = {0};
  put32(request, 0x43414553);
  put64(request + 4, 2);
  memcpy(request + 12, path, sizeof(path) - 1);
  int64_t result = native(588, endpoint, (uint64_t)request, sizeof(request),
                          (uint64_t)reply, sizeof(reply));
  uint64_t error = 1;
  memcpy(&error, reply, 8);
  return result >= 16 && error == 0;
}
int main(void) {
  _Static_assert(sizeof(struct context) == 176, "native context layout");
  fprintf(stderr, "snapshot-continuation: start\n");
  int64_t authority =
      N(518, "capability.service", strlen("capability.service"), 0);
  CHECK(authority > 0);
  uint64_t tls;
  /* This fixture's initial runtime TCB stores its own base in its first word.
   */
  __asm__ volatile("movq %%fs:0,%0" : "=r"(tls));
  struct context context = {0};
  CHECK(mochios_posix_capture_snapshot(&context, tls, fail_capture) ==
        (uint64_t)(int64_t)-ENOMEM);
  for (volatile unsigned attempt = 0; attempt < 3; attempt++) {
    private_value = 0x11;
    uint64_t image = mochios_posix_capture_snapshot(&context, tls, capture);
    if (image == 0) {
      uint64_t restored_tls;
      __asm__ volatile("movq %%fs:0,%0" : "=r"(restored_tls));
      int ok = private_value == 0x11 && restored_tls == tls;
      /* No runtime FD, thread-registration or POSIX-service state is inherited
       * by this deliberately empty native creation request. */
      N(574, ok ? 37 : 99, 0, 0);
      __builtin_unreachable();
    }
    CHECK((int64_t)image > 0);
    CHECK(context.entry != 0 && context.stack != 0 &&
          context.registers[0] == 0);
    private_value = 0x22;
    unsigned char bytes[512] = {0};
    size_t offset = 32 + sizeof(path) - 1 + sizeof(label) - 1;
    memcpy(bytes, "MCRT", 4);
    bytes[4] = 2;
    bytes[6] = 32;
    put32(bytes + 8, sizeof(path) - 1);
    put32(bytes + 12, sizeof(context));
    put32(bytes + 24, sizeof(label) - 1);
    put32(bytes + 28, 1);
    memcpy(bytes + 32, path, sizeof(path) - 1);
    memcpy(bytes + 32 + sizeof(path) - 1, label, sizeof(label) - 1);
    memcpy(bytes + offset, &context, sizeof(context));
    CHECK(authorize((uint64_t)authority));
    int64_t child = N(676, image, bytes, offset + sizeof(context));
    fprintf(stderr, "snapshot-continuation: create=%lld image=%llu "
                    "entry=%llx stack=%llx tls=%llx flags=%llx\n",
            (long long)child, (unsigned long long)image,
            (unsigned long long)context.entry, (unsigned long long)context.stack,
            (unsigned long long)context.tls, (unsigned long long)context.flags);
    CHECK(child > 0);
    CHECK(N(626, image, 0, 0) == 0);
    struct status state = {0};
    CHECK(N(642, child, &state, 0) == 0 && state.state == 1);
    CHECK(N(645, child, 0, 0) == 0);
    CHECK(N(643, child, UINT64_MAX, &state) == 0);
    CHECK(state.state == 2 && state.code == 37 && private_value == 0x22);
    CHECK(N(626, child, 0, 0) == 0);
  }
  fprintf(stderr,
          "snapshot-continuation: PASS actual userspace assembly, "
          "native VM clone, native creation, original caller stack, "
          "child zero, COW, TLS, error preservation, repeated cleanup\n");
  return 0;
}
