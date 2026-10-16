#include <stdatomic.h>
#define SOCKET_PEEK_TEST_ENTRY run_socket_peek_regressions
#include "native_socket_peek.c"
#undef CHECK
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "provider-lifetime: FAIL line=%u errno=%d %s\n",         \
              __LINE__, errno, #x);                                            \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static uint64_t life_native(uint64_t number, uint64_t a, uint64_t b, uint64_t c,
                            uint64_t d, uint64_t e, uint64_t f) {
  register uint64_t r10 __asm__("r10") = d;
  register uint64_t r8 __asm__("r8") = e;
  register uint64_t r9 __asm__("r9") = f;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return number;
}
struct life_handles {
  uint32_t count, flags;
  struct {
    uint32_t handle, reserved;
    uint64_t rights;
  } entries[4];
};
struct life_wait {
  uint32_t handle, minimum;
  uint64_t interests, observed;
};
struct life_request {
  uint32_t magic;
  uint16_t version, opcode;
  uint64_t object, argument, basis;
  uint32_t length, data_length;
  uint64_t reserved;
};
struct life_response {
  uint32_t magic;
  uint16_t version, opcode;
  int64_t status;
  uint64_t object, value;
  uint32_t data_length, reserved;
  char bytes[2];
};
static _Atomic uint32_t life_endpoint, life_object;
static _Atomic int life_release, life_error;
static int life_mode;
static uint32_t life_reply_pipe[2];

static void *life_provider(void *unused) {
  (void)unused;
  int64_t endpoint = (int64_t)life_native(629, 0, 0, 0, 0, 0, 0);
  if (endpoint <= 0) {
    atomic_store(&life_error, 1);
    return NULL;
  }
  /* READ | WAIT only: neither resource-control nor provider-name lookup. */
  int64_t object = (int64_t)life_native(637, endpoint, 9, 17, 0, 0, 0);
  if (object <= 0) {
    atomic_store(&life_error, 2);
    return NULL;
  }
  atomic_store(&life_endpoint, (uint32_t)endpoint);
  fprintf(stderr, "provider-lifetime: worker mode=%d ready\n", life_mode);
  atomic_store(&life_object, (uint32_t)object);
  if (life_mode == 0 || life_mode == 6) {
    while (!atomic_load(&life_release))
      sched_yield();
  } else {
    for (;;) {
      unsigned char request[4144];
      struct life_handles handles = {0};
      int64_t received =
          (int64_t)life_native(631, (uintptr_t)request, sizeof(request),
                               (uintptr_t)&handles, endpoint, 0, 0);
      if (received < 0) {
        atomic_store(&life_error, 3);
        break;
      }
      uint64_t sender = (uint64_t)received >> 32;
      if (life_mode == 3 || life_mode == 4)
        break; /* ordinary IPC call, deliberately no reply */
      struct life_request header;
      if ((uint32_t)received < sizeof(header)) {
        atomic_store(&life_error, 4);
        break;
      }
      memcpy(&header, request, sizeof(header));
      fprintf(stderr, "provider-lifetime: worker mode=%d opcode=%u\n",
              life_mode, header.opcode);
      struct life_response response = {.magic = header.magic,
                                       .version = header.version,
                                       .opcode = header.opcode,
                                       .object = header.object};
      if (header.opcode == 9)
        response.status = -95; /* no stable memory backing */
      else if (header.opcode == 1 && (life_mode == 2 || life_mode == 5)) {
        response.value = 2;
        response.data_length = 2;
        memcpy(response.bytes, "ok", 2);
      } else if (header.opcode == 1)
        break; /* received native READ, no reply */
      else {
        atomic_store(&life_error, 5);
        break;
      }
      int64_t sent;
      if (life_mode == 5 && header.opcode == 9) {
        // A native call without a Handle output must discard this unsolicited
        // reference, not install it or leak it while recycling its message.
        struct life_handles outgoing = {.count = 1};
        outgoing.entries[0].handle = life_reply_pipe[1];
        outgoing.entries[0].rights =
            2; /* WRITE, no control/transfer authority */
        sent = (int64_t)life_native(633, sender, (uintptr_t)&response, 40,
                                    (uintptr_t)&outgoing, 0, 0);
        if (life_native(626, life_reply_pipe[1], 0, 0, 0, 0, 0) != 0)
          atomic_store(&life_error, 7);
      } else {
        sent = (int64_t)life_native(589, sender, (uintptr_t)&response,
                                    40 + response.data_length, 0, 0, 0);
      }
      if (sent < 0) {
        atomic_store(&life_error, 6);
        break;
      }
      if (header.opcode == 1)
        break; /* committed reply, then endpoint death */
    }
  }
  fprintf(stderr, "provider-lifetime: worker mode=%d exiting\n", life_mode);
  return NULL;
}
static void *life_delayed_exit(void *unused) {
  (void)unused;
  pause_ms(100);
  atomic_store(&life_release, 1);
  return NULL;
}
static int life_start(int mode, pthread_t *thread) {
  life_mode = mode;
  atomic_store(&life_endpoint, 0);
  atomic_store(&life_object, 0);
  atomic_store(&life_release, 0);
  atomic_store(&life_error, 0);
  CHECK(pthread_create(thread, NULL, life_provider, NULL) == 0);
  fprintf(stderr, "provider-lifetime: created mode=%d\n", mode);
  while (!atomic_load(&life_object) && !atomic_load(&life_error))
    sched_yield();
  CHECK(!atomic_load(&life_error));
  return 0;
}
static int life_close(pthread_t provider) {
  CHECK(pthread_join(provider, NULL) == 0 && !atomic_load(&life_error));
  CHECK(life_native(626, atomic_load(&life_object), 0, 0, 0, 0, 0) == 0);
  CHECK(life_native(626, atomic_load(&life_endpoint), 0, 0, 0, 0, 0) == 0);
  return 0;
}
static int life_unread_queue(void) {
  for (unsigned round = 0; round < 8; round++) {
    pthread_t provider;
    uint32_t handles[2];
    CHECK(life_native(649, (uintptr_t)handles, 0, 0, 0, 0, 0) == 0);
    CHECK(life_start(6, &provider) == 0);
    struct life_handles outgoing = {.count = 1};
    outgoing.entries[0].handle = handles[1];
    outgoing.entries[0].rights = 2; /* each unread message owns a WRITE lease */
    unsigned queued = 0;
    for (unsigned n = 0; n < 64; n++) {
      int64_t sent = (int64_t)life_native(630, atomic_load(&life_endpoint),
                                          (uintptr_t) "unread", 6,
                                          (uintptr_t)&outgoing, 0, 0);
      if (sent == -11)
        break;
      CHECK(sent == 0);
      queued++;
    }
    CHECK(queued != 0);
    CHECK(life_native(626, handles[1], 0, 0, 0, 0, 0) == 0);
    struct life_wait eof = {.handle = handles[0], .interests = 2};
    CHECK((int64_t)life_native(647, (uintptr_t)&eof, 1, 0, 0, 0, 0) == INT64_C(-262137));
    // The receiver never reads these ordinary messages. It can still receive
    // its thread-cleanup RPC reply through the queue's reserved reply slot.
    atomic_store(&life_release, 1);
    CHECK(pthread_join(provider, NULL) == 0 && !atomic_load(&life_error));
    // No test thread is created between exit and this check: reclamation must
    // not depend on another receiver eventually reusing/draining the slot.
    int64_t ready = (int64_t)life_native(647, (uintptr_t)&eof, 1, 0, 0, 0, 0);
    fprintf(stderr, "provider-lifetime: unread round=%u queued=%u EOF=%lld\n",
            round, queued, (long long)ready);
    CHECK(ready == 0 && eof.observed == 2);
    // Holding the dead endpoint's Handle must not retain its unread queue.
    CHECK(life_native(626, atomic_load(&life_object), 0, 0, 0, 0, 0) == 0);
    CHECK(life_native(626, atomic_load(&life_endpoint), 0, 0, 0, 0, 0) == 0);
    CHECK(life_native(626, handles[0], 0, 0, 0, 0, 0) == 0);
  }
  puts("provider-lifetime: full unread queues release attached leases at "
       "endpoint exit PASS");
  return 0;
}
static int life_now(uint64_t *nanoseconds) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
    return -1;
  *nanoseconds = (uint64_t)value.tv_sec * UINT64_C(1000000000) +
                 (uint64_t)value.tv_nsec;
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 5 && !strcmp(argv[1], "--socket-exec"))
    return run_socket_peek_regressions(argc, argv);
  _Static_assert(sizeof(struct life_request) == 48, "provider request ABI");
  pthread_t provider, terminator;
  CHECK(life_start(0, &provider) == 0);
  CHECK(pthread_create(&terminator, NULL, life_delayed_exit, NULL) == 0);
  struct life_wait item = {.handle = atomic_load(&life_object), .interests = 2};
  uint64_t started, finished;
  CHECK(life_now(&started) == 0);
  CHECK((int64_t)life_native(647, (uintptr_t)&item, 1, started + 3000000000, 0,
                             0, 0) == -3);
  CHECK(life_now(&finished) == 0 && finished >= started);
  CHECK(finished - started >= 60000000 && finished - started < 2000000000);
  CHECK(pthread_join(terminator, NULL) == 0);
  CHECK(pthread_join(provider, NULL) == 0 && !atomic_load(&life_error));
  CHECK((int64_t)life_native(647, (uintptr_t)&item, 1, 0, 0, 0, 0) == -3);
  char output[2];
  CHECK((int64_t)life_native(634, item.handle, (uintptr_t)output, 2, 0, 0, 0) ==
        -3);
  CHECK(life_native(626, item.handle, 0, 0, 0, 0, 0) == 0);
  CHECK(life_native(626, atomic_load(&life_endpoint), 0, 0, 0, 0, 0) == 0);
  puts("provider-lifetime: parked and already-dead readiness waits fail closed "
       "PASS");

  for (int mode = 1; mode <= 5; mode++) {
    if (mode == 5)
      CHECK(life_native(649, (uintptr_t)life_reply_pipe, 0, 0, 0, 0, 0) == 0);
    fprintf(stderr, "provider-lifetime: testing in-flight mode=%d\n", mode);
    CHECK(life_start(mode, &provider) == 0);
    fprintf(stderr, "provider-lifetime: invoking mode=%d\n", mode);
    int64_t result;
    if (mode <= 2 || mode == 5)
      result = (int64_t)life_native(634, atomic_load(&life_object),
                                    (uintptr_t)output, 2, 0, 0, 0);
    else if (mode == 3)
      result =
          (int64_t)life_native(588, atomic_load(&life_endpoint),
                               (uintptr_t) "req", 3, (uintptr_t)output, 2, 0);
    else {
      struct life_handles handles = {0};
      result = (int64_t)life_native(632, atomic_load(&life_endpoint),
                                    (uintptr_t) "req", 3, (uintptr_t)output, 2,
                                    (uintptr_t)&handles);
    }
    CHECK(mode == 2 || mode == 5 ? result == 2 && !memcmp(output, "ok", 2)
                                 : result == -3);
    fprintf(stderr, "provider-lifetime: in-flight mode=%d result=%lld PASS\n",
            mode, (long long)result);
    CHECK(life_close(provider) == 0);
    if (mode == 5) {
      struct life_wait eof = {.handle = life_reply_pipe[0], .interests = 2};
      int64_t ready = (int64_t)life_native(647, (uintptr_t)&eof, 1, 0, 0, 0, 0);
      fprintf(stderr,
              "provider-lifetime: discarded attachment EOF result=%lld "
              "observed=%llu\n",
              (long long)ready, (unsigned long long)eof.observed);
      CHECK(ready == 0);
      CHECK(eof.observed == 2);
      CHECK(life_native(626, life_reply_pipe[0], 0, 0, 0, 0, 0) == 0);
      puts("provider-lifetime: discarded attachment releases final native "
           "stream reference PASS");
    }
  }
  puts("provider-lifetime: native read and plain/attached IPC death wakeups "
       "PASS");
  puts("provider-lifetime: committed reply survives owner exit PASS");
  CHECK(run_socket_peek_regressions(argc, argv) == 0);
  CHECK(life_unread_queue() == 0);
  puts("provider-lifetime: PASS native endpoint retirement and socket "
       "regressions");
  return 0;
}
