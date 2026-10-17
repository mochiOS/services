/* Real endpoint authority, private update Handles and shared/private PTEs.
 * Reuse the native syscall and provider wire helpers, not a host simulation. */
#define main unused_fault_retry_main
#include "native_vm_fault_retry.c"
#undef main
#undef CHECK

enum {
  HANDLE_DUPLICATE = 627,
  IPC_SEND = 630,
  HANDLE_RIGHTS_GET = 664,
  HANDLE_CONTROL = 668,
  HANDLE_READ_AT = 673,
  IMAGE_CLONE = 679,
  PROVIDER_MEMORY_UPDATE_CREATE = 697
};
static _Atomic int64_t owner_endpoint;
static size_t stored_length = 8192;

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "provider-memory-update: FAIL line %u: %s\n", __LINE__,  \
              #x);                                                             \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static int64_t control(uint64_t handle, uint64_t operation) {
  return native(HANDLE_CONTROL, handle, operation, 0, 0, 0, 0);
}

static void *update_provider(void *unused) {
  (void)unused;
  int64_t endpoint = native(ENDPOINT_CREATE, 0, 0, 0, 0, 0, 0);
  atomic_store_explicit(&owner_endpoint, endpoint, memory_order_release);
  if (endpoint < 0)
    return (void *)1;
  int64_t object = native(
      PROVIDER_CREATE, endpoint, 101,
      1 | 2 | 64 | 256 | (UINT64_C(1) << 62) | (UINT64_C(1) << 63), 0, 0, 0);
  atomic_store_explicit(&backing_handle, object, memory_order_release);
  if (object < 0)
    return (void *)2;
  for (;;) {
    unsigned char request[48];
    struct attachments attached = {0};
    int64_t message = native(IPC_RECV, (uintptr_t)request, sizeof(request),
                             (uintptr_t)&attached, endpoint, 0, 0);
    if (message < 0 || (uint32_t)message != sizeof(request) || attached.count ||
        attached.flags != 1 || memcmp(request, "MNUP\1\0", 6))
      return (void *)3;
    uint16_t opcode;
    memcpy(&opcode, request + 6, sizeof(opcode));
    if (get64(request + 8) != 101)
      return (void *)4;
    if (opcode == 4)
      break;
    unsigned char response[40 + 4096] = {0};
    memcpy(response, request, 8);
    put64(response + 16, 101);
    uint32_t count = 0;
    if (opcode == 9) {
      put64(response + 24, 77);
    } else if (opcode == 6) {
      uint64_t offset = get64(request + 24);
      uint32_t requested;
      memcpy(&requested, request + 32, sizeof(requested));
      if (offset > 8192 || requested > 4096)
        return (void *)5;
      count = offset >= stored_length ? 0 : stored_length - offset;
      if (count > requested)
        count = requested;
      put64(response + 24, count);
      memcpy(response + 32, &count, sizeof(count));
      memset(response + 40, offset ? 'b' : 'a', count);
#ifdef BEFORE_PROVIDER_READ_REPLY
      BEFORE_PROVIDER_READ_REPLY();
#endif
    } else if (opcode == 5 && get64(request + 24) == 100) {
      stored_length = 5000; /* explicit lower mutation, no kernel policy */
    } else if (opcode == 8) {
      /* OP_SYNC: this test provider has only RAM state, no persistent medium. */
    } else {
      return (void *)6;
    }
    struct attachments outgoing = {0};
    if (native(IPC_REPLY, (uint64_t)message >> 32, (uintptr_t)response,
               40 + count, (uintptr_t)&outgoing, 0, 0))
      return (void *)7;
  }
  return native(HANDLE_CLOSE, endpoint, 0, 0, 0, 0, 0) ? (void *)8 : NULL;
}

#ifndef PROVIDER_MEMORY_UPDATE_MAIN
#define PROVIDER_MEMORY_UPDATE_MAIN main
#endif
int PROVIDER_MEMORY_UPDATE_MAIN(void) {
  pthread_t thread;
  CHECK(pthread_create(&thread, NULL, update_provider, NULL) == 0);
  int64_t object;
  while (
      !(object = atomic_load_explicit(&backing_handle, memory_order_acquire)))
    sched_yield();
  CHECK(object > 0);
  int64_t endpoint =
      atomic_load_explicit(&owner_endpoint, memory_order_acquire);
  CHECK(endpoint > 0);
  CHECK(native(PROVIDER_CREATE, endpoint, UINT64_MAX, 1, 0, 0, 0) ==
        INT64_C(-262139));
  CHECK(native(PROVIDER_CREATE, endpoint, 102, UINT64_MAX, 0, 0, 0) ==
        INT64_C(-262139));
  CHECK(native(PROVIDER_CREATE, object, 102, 1, 0, 0, 0) ==
        INT64_C(-262138));
  /* Duplicate registration must not release or replace the live object. */
  CHECK(native(PROVIDER_CREATE, endpoint, 101, 1, 0, 0, 0) ==
        INT64_C(-262136));
  CHECK(native(PROVIDER_MEMORY_UPDATE_CREATE, object, 77, 8192, 5000, 0, 0) ==
        INT64_C(-262138));
  int64_t send_only = native(HANDLE_DUPLICATE, endpoint, 4, 0, 0, 0, 0);
  CHECK(send_only > 0);
  CHECK(native(PROVIDER_CREATE, send_only, 102, 1, 0, 0, 0) ==
        INT64_C(-262138));
  CHECK(native(PROVIDER_MEMORY_UPDATE_CREATE, send_only, 77, 8192, 5000, 0,
               0) == INT64_C(-262138));
  CHECK(native(HANDLE_CLOSE, send_only, 0, 0, 0, 0, 0) == 0);
  CHECK(native(PROVIDER_CREATE, send_only, 102, 1, 0, 0, 0) ==
        INT64_C(-262139));
  CHECK(native(PROVIDER_MEMORY_UPDATE_CREATE, send_only, 77, 8192, 5000, 0,
               0) == INT64_C(-262139));
  CHECK(native(PROVIDER_MEMORY_UPDATE_CREATE, endpoint, 0, 8192, 5000, 0, 0) ==
        INT64_C(-262139));
  int64_t private_address = native(MEMORY_MAP, 0, 8192, 3, 0, object, 0);
  int64_t shared_address = native(MEMORY_MAP, 0, 8192, 1, 2, object, 0);
  CHECK(private_address > 0 && shared_address > 0);
  volatile unsigned char *p = (void *)(uintptr_t)private_address;
  volatile unsigned char *s = (void *)(uintptr_t)shared_address;
  CHECK(p[0] == 'a' && p[8191] == 'b' && s[0] == 'a' && s[8191] == 'b');
  int64_t image = native(IMAGE_CLONE, 0, 0, 0, 0, 0, 0);
  CHECK(image > 0);
  p[0] = 'P'; /* unaffected private prefix must survive publication */
  CHECK(native(HANDLE_CLOSE, image, 0, 0, 0, 0, 0) == 0);
  int64_t unrelated_endpoint = native(ENDPOINT_CREATE, 0, 0, 0, 0, 0, 0);
  CHECK(unrelated_endpoint > 0);
  int64_t isolated = native(PROVIDER_MEMORY_UPDATE_CREATE, unrelated_endpoint,
                            77, 8192, 0, 0, 0);
  CHECK(isolated > 0 && control(isolated, 1) == 0);
  CHECK(native(HANDLE_CLOSE, isolated, 0, 0, 0, 0, 0) == 0);
  CHECK(native(MEMORY_PROTECT, private_address, 8192, 3, 0, 0, 0) == 0);
  CHECK(p[0] == 'P' && p[8191] == 'b'); /* same ID, different namespace */
  CHECK(native(HANDLE_CLOSE, unrelated_endpoint, 0, 0, 0, 0, 0) == 0);
  int64_t update =
      native(PROVIDER_MEMORY_UPDATE_CREATE, endpoint, 77, 8192, 5000, 0, 0);
  CHECK(update > 0);
  CHECK(native(HANDLE_RIGHTS_GET, update, 0, 0, 0, 0, 0) == 256);
  CHECK(native(HANDLE_DUPLICATE, update, 256, 0, 0, 0, 0) ==
        INT64_C(-262138));
  struct attachments outgoing = {.count = 1,
                                 .items = {{.handle = update, .rights = 256}}};
  CHECK(native(IPC_SEND, endpoint, 0, 0, (uintptr_t)&outgoing, 0, 0) == INT64_C(-262138));
  CHECK(control(update, 999) == -38);
  CHECK(control(update, 3) == INT64_C(-262139)); /* BEGIN cannot be skipped */
  CHECK(native(HANDLE_CONTROL, update, 1, 0, 1, 0, 0) == INT64_C(-262139));
  CHECK(native(MEMORY_PROTECT, private_address, 8192, 1, 0, 0, 0) ==
        INT64_C(-262137));
  CHECK(native(IMAGE_CLONE, 0, 0, 0, 0, 0, 0) == INT64_C(-262137));
  CHECK(native(HANDLE_CLOSE, update, 0, 0, 0, 0, 0) == 0); /* before BEGIN */
  CHECK(p[0] == 'P' && p[8191] == 'b');
  update =
      native(PROVIDER_MEMORY_UPDATE_CREATE, endpoint, 77, 8192, 5000, 0, 0);
  CHECK(update > 0 && control(update, 1) == 0);
  CHECK(control(update, 1) == INT64_C(-262139));
  CHECK(native(MEMORY_PROTECT, shared_address, 8192, 1, 0, 0, 0) ==
        INT64_C(-262137));
  CHECK(control(update, 2) == 0); /* confirmed unchanged */
  CHECK(native(HANDLE_CLOSE, update, 0, 0, 0, 0, 0) == 0);
  CHECK(p[0] == 'P' && p[8191] == 'b' && s[8191] == 'b');
  update =
      native(PROVIDER_MEMORY_UPDATE_CREATE, endpoint, 77, 8192, 5000, 0, 0);
  CHECK(update > 0 && control(update, 1) == 0);
  CHECK(control(object, 100) == 0);
  CHECK(control(update, 3) == 0); /* confirmed authoritative extent */
  CHECK(native(HANDLE_CLOSE, update, 0, 0, 0, 0, 0) == 0);
  CHECK(p[0] == 'P' && p[4999] == 'b' && p[5000] == 0 && p[8191] == 0);
  CHECK(s[0] == 'a' && s[4999] == 'b' && s[5000] == 0 && s[8191] == 0);
  update = native(PROVIDER_MEMORY_UPDATE_CREATE, endpoint, 77, 5000, 0, 0, 0);
  CHECK(update > 0 && control(update, 1) == 0);
  CHECK(native(HANDLE_CLOSE, update, 0, 0, 0, 0, 0) == 0); /* unknown outcome */
  CHECK(native(MEMORY_PROTECT, private_address, 8192, 1, 0, 0, 0) ==
        INT64_C(-262140));
  CHECK(native(MEMORY_PROTECT, shared_address, 8192, 1, 0, 0, 0) ==
        INT64_C(-262140));
  CHECK(native(IMAGE_CLONE, 0, 0, 0, 0, 0, 0) == INT64_C(-262140));
  unsigned char byte;
  CHECK(native(HANDLE_READ_AT, object, (uintptr_t)&byte, 1, 0, 0, 0) ==
        INT64_C(-262140));
  CHECK(native(MEMORY_UNMAP, private_address, 8192, 0, 0, 0, 0) == 0);
  CHECK(native(MEMORY_UNMAP, shared_address, 8192, 0, 0, 0, 0) == 0);
  CHECK(native(HANDLE_CLOSE, object, 0, 0, 0, 0, 0) == 0);
  void *result;
  CHECK(pthread_join(thread, &result) == 0 && result == NULL);
  puts("provider-memory-update: PASS owner authority, private Handle, "
       "cancellation, publication, clone failure provenance and "
       "unknown-outcome cleanup");
  return 0;
}
