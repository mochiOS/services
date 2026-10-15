/* Freestanding probe installed ONLY in the test fixture's posix.service role.
 * That role explicitly inherits filesystem CONTROL; ordinary applications do
 * not. No name lookup, PID lookup, libc startup or POSIX service is required.
 * A ticket from another provider deterministically exercises pre-storage
 * rescoping, then the actual filesystem-owned position crosses real IPC. */
#include <stddef.h>
#include <stdint.h>

enum {
  PROCESS_EXIT = 574,
  HANDLE_CLOSE = 626,
  LAUNCH_HANDLE_GET = 628,
  ENDPOINT_CREATE = 629,
  IPC_CALL = 632,
  HANDLE_SEEK = 636,
  HANDLE_WAIT_MANY = 647,
  DEBUG_WRITE = 660,
  HANDLE_RIGHTS_GET = 664,
  MEMORY_ADMISSION_CREATE = 698,
  OPEN_AT = 18,
  TRUNCATE_HANDLE = 23,
  UNLINK_AT = 28,
  TRUNCATE_AT = 30
};
#define TRANSFER (UINT64_C(1) << 63)
#define TICKET_RIGHTS (TRANSFER | 16)
#define ADMISSION (UINT32_C(1) << 31)
#define ATTACHED (UINT32_C(1) << 30)
#define BUSY (-0x10002)
struct object {
  uint32_t handle, reserved;
  uint64_t rights;
};
struct attachments {
  uint32_t count, flags;
  struct object items[4];
};
struct wait_item {
  uint32_t handle, minimum;
  uint64_t interests, observed;
};
static uint32_t filesystem;
static uint64_t sequence;
static unsigned char response[64];
static const char path[] = "/tmp/native-filesystem-admission";

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
static void say(const char *text) {
  size_t len = 0;
  while (text[len])
    ++len;
  native(DEBUG_WRITE, (uintptr_t)text, len, 0, 0, 0, 0);
}
static _Noreturn void finish(unsigned status) {
  native(PROCESS_EXIT, status, 0, 0, 0, 0, 0);
  for (;;)
    __asm__ volatile("pause");
}
#define STR1(x) #x
#define STR(x) STR1(x)
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      say("filesystem-admission: FAIL line " STR(__LINE__) ": " #x "\n");      \
      finish(1);                                                               \
    }                                                                          \
  } while (0)
static void put(unsigned char *bytes, unsigned offset, uint64_t value,
                unsigned len) {
  for (unsigned i = 0; i < len; ++i)
    bytes[offset + i] = value >> (i * 8);
}
static uint64_t get(const unsigned char *bytes, unsigned offset, unsigned len) {
  uint64_t value = 0;
  for (unsigned i = 0; i < len; ++i)
    value |= (uint64_t)bytes[offset + i] << (i * 8);
  return value;
}
static int status(uint16_t op, uint32_t flags, uint64_t length,
                  struct attachments *objects) {
  unsigned char request[128] = {0};
  request[0] = 'M';
  request[1] = 'F';
  request[2] = 'S';
  request[3] = '1';
  put(request, 4, 1, 2);
  put(request, 6, op, 2);
  put(request, 8, ++sequence, 8);
  put(request, op == TRUNCATE_HANDLE ? 40 : 32, length, 8);
  put(request, 52, flags, 4);
  put(request, 60, 0600, 4);
  size_t payload = 0;
  if (op != TRUNCATE_HANDLE) {
    /* uid=gid=0, zero supplementary groups, followed by the path. */
    payload = 12 + sizeof(path) - 1;
    for (size_t i = 0; i < sizeof(path) - 1; ++i)
      request[76 + i] = path[i];
  }
  put(request, 48, payload, 4);
  int64_t result =
      native(IPC_CALL, filesystem, (uintptr_t)request, 64 + payload,
             (uintptr_t)response, sizeof(response), (uintptr_t)objects);
  CHECK(result >= 0 && (uint32_t)result == sizeof(response));
  CHECK(get(response, 0, 4) == UINT32_C(0x3153464d));
  CHECK(get(response, 4, 2) == 1 && get(response, 6, 2) == 0x8000);
  CHECK(get(response, 8, 8) == sequence && get(response, 48, 4) == 0);
  return (int32_t)get(response, 56, 4);
}
static void close_handle(uint32_t handle) {
  CHECK(native(HANDLE_CLOSE, handle, 0, 0, 0, 0, 0) == 0);
}
static uint64_t size(uint32_t file) {
  int64_t result = native(HANDLE_SEEK, file, 0, UINT64_C(0x4d4e5503), 0, 0, 0);
  CHECK(result >= 0);
  return result;
}
static uint64_t signals(uint32_t ticket) {
  struct wait_item item = {ticket, 0, 2 | 8, 0};
  CHECK(native(HANDLE_WAIT_MANY, (uintptr_t)&item, 1, 0, 0, 0, 0) == 0);
  return item.observed;
}

void probe(void) {
  say("filesystem-admission: starting explicitly delegated control IPC "
      "checks\n");
  int64_t endpoint =
      native(LAUNCH_HANDLE_GET, UINT64_C(0x4c5254433153464d), 0, 0, 0, 0, 0);
  CHECK(endpoint > 0);
  filesystem = endpoint;
  struct attachments objects = {0};
  CHECK(status(OPEN_AT, ADMISSION | 1 | 2 | 4 | 8, 0, &objects) == 0);
  CHECK(objects.count == 1 && objects.items[0].handle != 0);
  struct object file = objects.items[0];
  objects = (struct attachments){.count = 1, .items = {file}};
  CHECK(status(TRUNCATE_HANDLE, ADMISSION, 8192, &objects) == 0 &&
        objects.count == 0);
  CHECK(size(file.handle) == 8192);
  int64_t own_endpoint = native(ENDPOINT_CREATE, 0, 0, 0, 0, 0, 0);
  CHECK(own_endpoint > 0);
  for (unsigned operation = 0; operation < 3; ++operation) {
    int64_t unrelated =
        native(MEMORY_ADMISSION_CREATE, own_endpoint, 77, 0, 0, 0, 0);
    CHECK(unrelated > 0);
    struct object wrong = {(uint32_t)unrelated, 0, TICKET_RIGHTS};
    uint16_t opcode = operation == 0   ? TRUNCATE_HANDLE
                      : operation == 1 ? TRUNCATE_AT
                                       : OPEN_AT;
    uint32_t flags = ADMISSION | ATTACHED | (operation == 2 ? 1 | 2 | 16 : 0);
    objects = (struct attachments){0};
    if (operation == 0)
      objects.items[objects.count++] = file;
    objects.items[objects.count++] = wrong;
    uint64_t before = size(file.handle);
    CHECK(status(opcode, flags, 5000, &objects) == BUSY);
    CHECK(objects.count == 1 && objects.items[0].rights == TICKET_RIGHTS);
    uint32_t ticket = objects.items[0].handle;
    CHECK(ticket != (uint32_t)unrelated);
    close_handle(unrelated);
    CHECK(native(HANDLE_RIGHTS_GET, ticket, 0, 0, 0, 0, 0) ==
          (int64_t)TICKET_RIGHTS);
    CHECK(signals(ticket) == 2 && size(file.handle) == before);
    if (operation == 0) {
      /* A rejected FileHandle cannot consume an otherwise valid position. */
      struct object read_only = file;
      read_only.rights = TRANSFER | 1;
      objects = (struct attachments){
          .count = 2, .items = {read_only, {ticket, 0, TICKET_RIGHTS}}};
      CHECK(status(TRUNCATE_HANDLE, ADMISSION | ATTACHED, 5000, &objects) ==
            -13);
      CHECK(objects.count == 0 && signals(ticket) == 2 &&
            size(file.handle) == before);
    }
    objects = (struct attachments){0};
    if (operation == 0)
      objects.items[objects.count++] = file;
    objects.items[objects.count++] = (struct object){ticket, 0, TICKET_RIGHTS};
    CHECK(status(opcode, flags, 5000, &objects) == 0);
    if (operation == 2) {
      CHECK(objects.count == 1);
      close_handle(objects.items[0].handle);
    } else
      CHECK(objects.count == 0);
    CHECK(signals(ticket) == 8);
    CHECK(size(file.handle) == (operation == 2 ? 0 : 5000));
    close_handle(ticket);
  }
  close_handle(own_endpoint);
  close_handle(file.handle);
  objects = (struct attachments){0};
  CHECK(status(UNLINK_AT, 0, 0, &objects) == 0 && objects.count == 0);
  say("filesystem-admission: PASS real IPC tickets, preflight rejection and "
      "three atomic mutation paths\n");
  finish(0);
}

__asm__(".section .text._start,\"ax\"\n.global _start\n_start:\n"
        "andq $-16,%rsp\ncall probe\nud2\n");
