/* Queue tickets are waitable/transferable, not mutation capabilities. Keep a
 * real provider read in flight to test wakeup and ordered guard consumption. */
static void pause_before_reply(void);
#define BEFORE_PROVIDER_READ_REPLY pause_before_reply
#define PROVIDER_MEMORY_UPDATE_MAIN unused_memory_update_main
#include "native_provider_memory_update.c"
#undef CHECK

enum { HANDLE_WAIT_MANY = 647, PROVIDER_MEMORY_ADMISSION_CREATE = 698 };
struct wait_item {
  uint32_t handle, minimum;
  uint64_t interests, observed;
};
static _Atomic int pause_enabled, paused, release_read, read_done, second_done,
    wait_entered;
static int64_t first_read_result, second_read_result, wait_result;
static uint64_t waiter_observed, wait_handle;

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "memory-admission: FAIL line %u: %s\n", __LINE__, #x);   \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static void pause_before_reply(void) {
  if (atomic_load(&pause_enabled) && !atomic_exchange(&paused, 1)) {
    while (!atomic_load(&release_read))
      sched_yield();
  }
}
static void *read_first(void *unused) {
  (void)unused;
  unsigned char byte;
  first_read_result = native(HANDLE_READ_AT, atomic_load(&backing_handle),
                             (uintptr_t)&byte, 1, 0, 0, 0);
  atomic_store(&read_done, 1);
  return NULL;
}
static void *read_second(void *unused) {
  (void)unused;
  unsigned char byte;
  second_read_result = native(HANDLE_READ_AT, atomic_load(&backing_handle),
                              (uintptr_t)&byte, 1, 0, 0, 0);
  atomic_store(&second_done, 1);
  return NULL;
}
static int64_t poll_ticket(uint64_t handle, uint64_t *observed) {
  struct wait_item item = {.handle = handle, .interests = 2 | 8};
  int64_t result = native(HANDLE_WAIT_MANY, (uintptr_t)&item, 1, 0, 0, 0, 0);
  *observed = item.observed;
  return result;
}
static void *wait_ticket(void *unused) {
  (void)unused;
  struct wait_item item = {.handle = wait_handle, .interests = 2 | 8};
  atomic_store(&wait_entered, 1);
  wait_result =
      native(HANDLE_WAIT_MANY, (uintptr_t)&item, 1, UINT64_MAX, 0, 0, 0);
  waiter_observed = item.observed;
  return NULL;
}

int main(void) {
  fprintf(stderr,
          "memory-admission: starting native ownership/wakeup checks\n");
  pthread_t provider_thread, reader, next_reader, waiter;
  CHECK(pthread_create(&provider_thread, NULL, update_provider, NULL) == 0);
  int64_t object;
  while (!(object = atomic_load(&backing_handle)))
    sched_yield();
  CHECK(object > 0);
  int64_t endpoint = atomic_load(&owner_endpoint);
  CHECK(native(PROVIDER_MEMORY_ADMISSION_CREATE, object, 77, 0, 0, 0, 0) ==
        -13);
  CHECK(native(PROVIDER_MEMORY_ADMISSION_CREATE, endpoint, 0, 0, 0, 0, 0) ==
        -22);
  int64_t send_only = native(HANDLE_DUPLICATE, endpoint, 4, 0, 0, 0, 0);
  CHECK(send_only > 0);
  CHECK(native(PROVIDER_MEMORY_ADMISSION_CREATE, send_only, 77, 0, 0, 0, 0) ==
        -13);
  CHECK(native(HANDLE_CLOSE, send_only, 0, 0, 0, 0, 0) == 0);
  int64_t private_address = native(MEMORY_MAP, 0, 8192, 3, 0, object, 0);
  int64_t shared_address = native(MEMORY_MAP, 0, 8192, 1, 2, object, 0);
  CHECK(private_address > 0 && shared_address > 0);
  volatile unsigned char *private_bytes = (void *)(uintptr_t)private_address;
  volatile unsigned char *shared = (void *)(uintptr_t)shared_address;
  CHECK(private_bytes[0] == 'a' && private_bytes[8191] == 'b');
  CHECK(shared[0] == 'a' && shared[8191] == 'b');
  private_bytes[0] = 'P';
  atomic_store(&pause_enabled, 1);
  CHECK(pthread_create(&reader, NULL, read_first, NULL) == 0);
  while (!atomic_load(&paused) && !atomic_load(&read_done))
    sched_yield();
  CHECK(atomic_load(&paused) && !atomic_load(&read_done));
  int64_t first =
      native(PROVIDER_MEMORY_ADMISSION_CREATE, endpoint, 77, 0, 0, 0, 0);
  int64_t second =
      native(PROVIDER_MEMORY_ADMISSION_CREATE, endpoint, 77, 0, 0, 0, 0);
  CHECK(first > 0 && second > 0);
  // A sleeping wait registration is NOT a queue owner. Final Handle close
  // must cancel and wake the waiter, not retain a position via its stack.
  int64_t cancelled =
      native(PROVIDER_MEMORY_ADMISSION_CREATE, endpoint, 77, 0, 0, 0, 0);
  CHECK(cancelled > 0);
  wait_handle = cancelled;
  CHECK(pthread_create(&waiter, NULL, wait_ticket, NULL) == 0);
  while (!atomic_load(&wait_entered))
    sched_yield();
  for (int i = 0; i < 128; ++i)
    sched_yield();
  CHECK(native(HANDLE_CLOSE, cancelled, 0, 0, 0, 0, 0) == 0);
  CHECK(pthread_join(waiter, NULL) == 0 && wait_result == -9);
  atomic_store(&wait_entered, 0);
  const uint64_t rights = 16 | (UINT64_C(1) << 63);
  CHECK((uint64_t)native(HANDLE_RIGHTS_GET, first, 0, 0, 0, 0, 0) == rights);
  CHECK(native(HANDLE_DUPLICATE, first, rights, 0, 0, 0, 0) == -13);
  CHECK(control(first, 1) == -13);
  CHECK(native(PROVIDER_MEMORY_UPDATE_CREATE, endpoint, 77, 8192, 5000, first,
               0) == -11);
  CHECK(native(PROVIDER_MEMORY_UPDATE_CREATE, endpoint, 78, 8192, 5000, first,
               0) == -13);
  int64_t other_endpoint = native(ENDPOINT_CREATE, 0, 0, 0, 0, 0, 0);
  CHECK(other_endpoint > 0);
  CHECK(native(PROVIDER_MEMORY_UPDATE_CREATE, other_endpoint, 77, 8192, 5000,
               first, 0) == -13);
  // IPC installs a distinct receiver reference; closing the original does not
  // cancel the surviving position. Receiver rights remain attenuated.
  struct attachments outgoing = {
      .count = 1, .items = {{.handle = first, .rights = rights}}};
  CHECK(native(IPC_SEND, other_endpoint, 0, 0, (uintptr_t)&outgoing, 0, 0) ==
        0);
  unsigned char byte;
  struct attachments received = {0};
  CHECK(native(IPC_RECV, (uintptr_t)&byte, 1, (uintptr_t)&received,
               other_endpoint, 0, 0) >= 0);
  CHECK(received.count == 1 && received.items[0].rights == rights);
  CHECK(received.items[0].handle != first);
  CHECK(native(HANDLE_CLOSE, first, 0, 0, 0, 0, 0) == 0);
  first = received.items[0].handle;
  uint64_t observed;
  CHECK(poll_ticket(first, &observed) == -11 && observed == 0);
  CHECK(poll_ticket(second, &observed) == -11 && observed == 0);
  CHECK(pthread_create(&next_reader, NULL, read_second, NULL) == 0);
  wait_handle = first;
  CHECK(pthread_create(&waiter, NULL, wait_ticket, NULL) == 0);
  while (!atomic_load(&wait_entered))
    sched_yield();
  for (int i = 0; i < 128; ++i)
    sched_yield();
  atomic_store(&release_read, 1);
  CHECK(pthread_join(reader, NULL) == 0 && first_read_result == 1);
  CHECK(pthread_join(waiter, NULL) == 0 && wait_result == 0 &&
        waiter_observed == 2);
  CHECK(!atomic_load(&second_done));
  CHECK(native(PROVIDER_MEMORY_UPDATE_CREATE, endpoint, 77, 8192, 5000, second,
               0) == -11);
  int64_t update =
      native(PROVIDER_MEMORY_UPDATE_CREATE, endpoint, 77, 8192, 5000, first, 0);
  CHECK(update > 0);
  CHECK(poll_ticket(first, &observed) == 0 && observed == 8);
  CHECK(native(PROVIDER_MEMORY_UPDATE_CREATE, endpoint, 77, 8192, 5000, first,
               0) == -22);
  CHECK(native(HANDLE_CLOSE, first, 0, 0, 0, 0, 0) == 0);
  CHECK(control(update, 1) == 0);
  CHECK(native(MEMORY_PROTECT, private_address, 8192, 1, 0, 0, 0) ==
        INT64_C(-262137));
  CHECK(control(object, 100) ==
        0); // provider makes the new extent authoritative
  CHECK(control(update, 3) == 0);
  CHECK(private_bytes[0] == 'P' && private_bytes[4999] == 'b');
  CHECK(private_bytes[5000] == 0 && private_bytes[8191] == 0);
  CHECK(shared[0] == 'a' && shared[4999] == 'b');
  CHECK(shared[5000] == 0 && shared[8191] == 0);
  CHECK(native(HANDLE_CLOSE, update, 0, 0, 0, 0, 0) == 0);
  CHECK(poll_ticket(second, &observed) == 0 && observed == 2);
  CHECK(!atomic_load(&second_done));
  CHECK(native(HANDLE_CLOSE, second, 0, 0, 0, 0, 0) == 0);
  CHECK(pthread_join(next_reader, NULL) == 0 && second_read_result == 1);
  int64_t orphan =
      native(PROVIDER_MEMORY_ADMISSION_CREATE, endpoint, 88, 0, 0, 0, 0);
  CHECK(orphan > 0);
  CHECK(native(MEMORY_UNMAP, private_address, 8192, 0, 0, 0, 0) == 0);
  CHECK(native(MEMORY_UNMAP, shared_address, 8192, 0, 0, 0, 0) == 0);
  CHECK(native(HANDLE_CLOSE, object, 0, 0, 0, 0, 0) == 0);
  void *provider_result;
  CHECK(pthread_join(provider_thread, &provider_result) == 0 &&
        provider_result == NULL);
  CHECK(poll_ticket(orphan, &observed) == -3);
  CHECK(native(HANDLE_CLOSE, orphan, 0, 0, 0, 0, 0) == 0);
  CHECK(native(HANDLE_CLOSE, other_endpoint, 0, 0, 0, 0, 0) == 0);
  puts("memory-admission: PASS authority, IPC transfer, cancellation, FIFO "
       "wakeup and scoped consumption");
  return 0;
}
