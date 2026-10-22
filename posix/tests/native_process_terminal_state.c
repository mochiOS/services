/* Isolated KVM probe installed as compositor.service. Child creation still
 * uses the existing execution authority; no extra capabilities are granted. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define NATIVE_RESOURCE_UNAVAILABLE INT64_C(-262141)

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
  uint64_t image_revision;
};
struct context {
  uint64_t entry, stack, argument, tls, flags, reserved[3];
  uint64_t registers[14];
};
static unsigned char stack[65536] __attribute__((aligned(16)));
static unsigned char worker_stacks[6][32768] __attribute__((aligned(16)));
struct shared_state {
  uint64_t ticks, ready, go, failed;
};
static struct shared_state *shared;
static const char path[] = "/system/services/compositor.service";
static const char label[] = "terminal-child";
static void put32(void *p, uint32_t value) { memcpy(p, &value, 4); }
static uint64_t load(uint64_t *p) {
  return __atomic_load_n(p, __ATOMIC_SEQ_CST);
}
static void store(uint64_t *p, uint64_t value) {
  __atomic_store_n(p, value, __ATOMIC_SEQ_CST);
}
__attribute__((used, noreturn)) static void worker(uint64_t mode) {
  __atomic_fetch_add(&shared->ready, 1, __ATOMIC_SEQ_CST);
  for (;;) {
    __atomic_fetch_add(&shared->ticks, 1, __ATOMIC_SEQ_CST);
    if (mode && load(&shared->go)) {
      N(mode == 1 ? 574 : 578, 37, 0, 0);
      __builtin_unreachable();
    }
  }
}
__attribute__((naked)) static void worker_entry(void) {
  __asm__ volatile("call worker\n\tud2");
}
__attribute__((used, noreturn)) static void child(uint64_t code) {
  if (code >= 256) {
    unsigned mode = (unsigned)(code - 256);
    for (unsigned index = 0; index < (mode == 2 ? 1 : 6); ++index) {
      struct context context = {0};
      context.entry = (uint64_t)worker_entry;
      context.stack =
          (uint64_t)(worker_stacks[index] + sizeof(worker_stacks[0]));
      context.argument = index == 0 ? mode : 0;
      int64_t result = N(577, &context, sizeof(context), 0);
      if (result < 0 && result != NATIVE_RESOURCE_UNAVAILABLE)
        store(&shared->failed, (uint64_t)-result);
    }
    for (;;) {
      __atomic_fetch_add(&shared->ticks, 1, __ATOMIC_SEQ_CST);
      if (mode == 2 && load(&shared->go)) {
        N(578, 37, 0, 0);
        __builtin_unreachable();
      }
    }
  }
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
  _Static_assert(sizeof(struct status) == 32, "native retained status");
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
      int64_t result;
      unsigned retries = 0;
      do {
        result = N(646, handle, UINT64_MAX, 0);
        if (result == INT64_C(-262137))
          N(517, 1, 0, 0);
      } while (result == INT64_C(-262137) && ++retries < 1000);
      CHECK(result == 0 || result == INT64_C(-262135));
      expected = result == 0 ? UINT64_MAX : code;
      forced += result == 0;
      natural += result == INT64_C(-262135);
      CHECK(N(643, handle, UINT64_MAX, &status) == 0);
    }
    CHECK(status.state == 2 && status.reserved == 0 && status.code == expected);
    /* Retain the handle across reclamation and attempt to replace its code. */
    CHECK(N(517, 2, 0, 0) == 0);
    CHECK(N(646, handle, 123, 0) == INT64_C(-262135));
    CHECK(N(642, handle, &status, 0) == 0);
    CHECK(status.state == 2 && status.code == expected);
    CHECK(N(626, handle, 0, 0) == 0);
  }
  CHECK(forced > 0 && natural >= 2);
  fprintf(stderr,
          "terminal-state: PASS 20 trials, natural=%u forced=%u, zero "
          "and full-width codes, races, retained handles\n",
          natural, forced);
  int64_t memory = N(671, 4096, 0, 0);
  CHECK(memory > 0);
  int64_t address = native6(582, 0, 4096, 3, 2, (uint64_t)memory, 0);
  CHECK(address > 0);
  shared = (struct shared_state *)(uintptr_t)address;
  for (unsigned index = 0; index < 6; ++index)
    for (size_t page = 0; page < sizeof(worker_stacks[0]); page += 4096)
      worker_stacks[index][page] = 1;
  for (unsigned mode = 0; mode < 3; ++mode) {
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
      memset(shared, 0, sizeof(*shared));
      int64_t handle = create((uint64_t)authority, 256 + mode);
      CHECK(handle > 0);
      CHECK(N(645, handle, 0, 0) == 0);
      unsigned spins;
      for (spins = 0;
           spins < 5000 && (!load(&shared->ready) || !load(&shared->ticks));
           ++spins)
        CHECK(N(517, 1, 0, 0) == 0);
      CHECK(load(&shared->ready) && load(&shared->ticks));
      if (mode == 0)
        CHECK(N(646, handle, 137, 0) == 0);
      else
        store(&shared->go, 1);
      struct status status = {0};
      /* Deadline bounds a missing last-thread publication without polling it.
       */
      struct {
        uint64_t seconds;
        uint32_t nanoseconds, reserved;
      } now = {0};
      CHECK(N(640, UINT64_C(0x4d4e55434c4b0002), &now, 0) == 0);
      uint64_t deadline =
          (now.seconds + 10) * UINT64_C(1000000000) + now.nanoseconds;
      CHECK(N(643, handle, deadline, &status) == 0);
      CHECK(status.state == 2 && status.code == (mode == 0 ? 137 : 37));
      uint64_t stopped = load(&shared->ticks);
      CHECK(N(517, 5, 0, 0) == 0);
      CHECK(load(&shared->ticks) == stopped && !load(&shared->failed));
      CHECK(N(626, handle, 0, 0) == 0);
    }
    fprintf(stderr, "process-quiescence: mode=%u PASS 8 trials\n", mode);
  }
  CHECK(N(583, address, 4096, 0) == 0);
  CHECK(N(626, memory, 0, 0) == 0);
  fprintf(stderr, "process-quiescence: PASS external termination, self exit "
                  "during creation, concurrent last-thread exit; shared "
                  "heartbeat stops before exit is observable\n");
  return 0;
}
