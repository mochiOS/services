/* Deterministic hardware-fault retry: a native provider returns EAGAIN three
 * times for each private/shared page, then supplies the actual backing bytes.
 */
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

enum {
  MEMORY_MAP = 582,
  MEMORY_UNMAP = 583,
  HANDLE_CLOSE = 626,
  ENDPOINT_CREATE = 629,
  IPC_RECV = 631,
  IPC_REPLY = 633,
  PROVIDER_CREATE = 637
};
struct attachment {
  uint32_t handle, reserved;
  uint64_t rights;
};
struct attachments {
  uint32_t count, flags;
  struct attachment items[4];
};
static _Atomic int64_t backing_handle;
static unsigned reads[2];

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "vm-fault-retry: FAIL line %u: %s\n", __LINE__, #x);     \
      return 1;                                                                \
    }                                                                          \
  } while (0)

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
static uint64_t get64(const unsigned char *bytes) {
  uint64_t value;
  memcpy(&value, bytes, sizeof(value));
  return value;
}
static void put64(unsigned char *bytes, uint64_t value) {
  memcpy(bytes, &value, sizeof(value));
}

static void unexpected_fault(int signal_number) {
  (void)signal_number;
  static const char message[] =
      "vm-fault-retry: FAIL transient fault delivered as exception\n";
  (void)write(2, message, sizeof(message) - 1);
  _exit(91);
}

static void *provider(void *argument) {
  (void)argument;
  int64_t endpoint = native(ENDPOINT_CREATE, 0, 0, 0, 0, 0, 0);
  if (endpoint < 0) {
    atomic_store_explicit(&backing_handle, endpoint, memory_order_release);
    return (void *)1;
  }
  int64_t object = native(PROVIDER_CREATE, endpoint, 101, 1 | 64, 0, 0, 0);
  atomic_store_explicit(&backing_handle, object, memory_order_release);
  if (object < 0)
    return (void *)2;
  for (;;) {
    unsigned char request[48];
    struct attachments received = {0};
    int64_t message = native(IPC_RECV, (uintptr_t)request, sizeof(request),
                             (uintptr_t)&received, endpoint, 0, 0);
    if (message < 0 || (uint32_t)message != sizeof(request) ||
        received.count != 0 || received.flags != 1 ||
        memcmp(request, "MNUP\1\0", 6) || get64(request + 8) != 101)
      return (void *)3;
    uint16_t opcode;
    memcpy(&opcode, request + 6, sizeof(opcode));
    if (opcode == 4)
      break; /* final native reference release, not a call */
    unsigned char response[40 + 4096] = {0};
    memcpy(response, request, 8);
    put64(response + 16, 101);
    uint32_t data_length = 0;
    if (opcode == 9) {
      put64(response + 24, 77); /* opaque backing identity */
    } else if (opcode == 6) {
      uint64_t offset = get64(request + 24);
      uint32_t length;
      memcpy(&length, request + 32, sizeof(length));
      if ((offset != 0 && offset != 4096) || length != 4096)
        return (void *)4;
      unsigned page = (unsigned)(offset / 4096);
      if (++reads[page] <= 3) {
        put64(response + 8, (uint64_t)(int64_t)-11);
      } else {
        data_length = 4096;
        put64(response + 24, data_length);
        memcpy(response + 32, &data_length, sizeof(data_length));
        memset(response + 40, 'a' + page, data_length);
      }
    } else {
      return (void *)5;
    }
    struct attachments outgoing = {0};
    if (native(IPC_REPLY, (uint64_t)message >> 32, (uintptr_t)response,
               40 + data_length, (uintptr_t)&outgoing, 0, 0) != 0)
      return (void *)6;
  }
  return native(HANDLE_CLOSE, endpoint, 0, 0, 0, 0, 0) == 0 ? NULL : (void *)7;
}

int main(void) {
  struct sigaction action = {0};
  action.sa_handler = unexpected_fault;
  CHECK(sigemptyset(&action.sa_mask) == 0);
  CHECK(sigaction(SIGBUS, &action, NULL) == 0);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  pthread_t thread;
  CHECK(pthread_create(&thread, NULL, provider, NULL) == 0);
  int64_t handle;
  while ((handle =
              atomic_load_explicit(&backing_handle, memory_order_acquire)) == 0)
    sched_yield();
  CHECK(handle > 0);
  int64_t private_address = native(MEMORY_MAP, 0, 4096, 1, 0, handle, 0);
  CHECK(private_address > 0);
  int64_t shared_address = native(MEMORY_MAP, 0, 4096, 1, 2, handle, 4096);
  CHECK(shared_address > 0);
  volatile unsigned char *private_bytes = (void *)(uintptr_t)private_address;
  volatile unsigned char *shared_bytes = (void *)(uintptr_t)shared_address;
  CHECK(private_bytes[0] == 'a' && private_bytes[4095] == 'a');
  CHECK(shared_bytes[0] == 'b' && shared_bytes[4095] == 'b');
  CHECK(native(MEMORY_UNMAP, private_address, 4096, 0, 0, 0, 0) == 0);
  CHECK(native(MEMORY_UNMAP, shared_address, 4096, 0, 0, 0, 0) == 0);
  CHECK(native(HANDLE_CLOSE, handle, 0, 0, 0, 0, 0) == 0);
  void *result;
  CHECK(pthread_join(thread, &result) == 0 && result == NULL);
  CHECK(reads[0] == 4 && reads[1] == 4);
  puts("vm-fault-retry: PASS private/shared hardware faults retry three EAGAIN "
       "replies without exceptions");
  return 0;
}
