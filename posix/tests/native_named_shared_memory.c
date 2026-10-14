#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct header {
  char magic[4];
  uint16_t version, opcode;
  uint64_t request;
  uint32_t flags, length;
  int32_t status;
  uint32_t reserved;
};
struct attachment {
  uint32_t handle, reserved;
  uint64_t rights;
};
struct handles {
  uint32_t count, flags;
  struct attachment entries[4];
};
_Static_assert(sizeof(struct header) == 32, "POSIX header");
_Static_assert(sizeof(struct handles) == 72, "native attachments");
enum {
  OPEN = 76,
  UNLINK = 77,
  BACKING = 78,
  CONTEXT_GET = 628,
  IPC_CALL = 632,
  MAP = 582,
  UNMAP = 583,
  CLOSE = 626,
  RIGHTS = 664,
  SAME = 666,
  LENGTH = 672,
  RESIZE = 686,
  CONTROL = 668,
  READ = 634,
  WRITE = 635,
  SEEK = 636
};
#define RO_RIGHTS (UINT64_C(385) | (UINT64_C(3) << 62))
#define RW_RIGHTS (RO_RIGHTS | UINT64_C(2))
#define MAP_RO_RIGHTS (UINT64_C(65) | (UINT64_C(3) << 62))
#define SEEK_START UINT64_C(0x4d4e5501)
#define SEEK_CURRENT UINT64_C(0x4d4e5502)
static uint64_t native(uint64_t number, uint64_t a, uint64_t b, uint64_t c,
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
#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "named-shared-memory: FAIL line=%u condition=%s\n",      \
              __LINE__, #condition);                                           \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static int request(uint64_t endpoint, uint16_t opcode, uint32_t options,
                   struct handles *handles) {
  const char *name = "/native-named-memory";
  unsigned char bytes[128] = {0};
  struct header header = {{'P', 'O', 'S', 'X'}, 1, opcode, 123, 0, 0, 0, 0};
  uint32_t length = (uint32_t)strlen(name);
  if (opcode == OPEN) {
    uint32_t fields[4] = {options, options & 2 ? 0600 : 0, 0, length};
    header.length = 16 + length;
    memcpy(bytes + 32, fields, 16);
    memcpy(bytes + 48, name, length);
  } else if (opcode == BACKING) {
    header.length = 4;
    memcpy(bytes + 32, &options, 4);
  } else {
    header.length = 4 + length;
    memcpy(bytes + 32, &length, 4);
    memcpy(bytes + 36, name, length);
  }
  memcpy(bytes, &header, 32);
  struct header response = {0};
  uint64_t result =
      native(IPC_CALL, endpoint, (uintptr_t)bytes, 32 + header.length,
             (uintptr_t)&response, sizeof(response), (uintptr_t)handles);
  if ((int64_t)result < 0 || (uint32_t)result != 32 ||
      response.request != 123 || memcmp(response.magic, "POSX", 4) ||
      response.version != 1 || response.opcode != 0x8000 || response.length ||
      response.flags || response.reserved || handles->flags)
    return -999;
  return response.status;
}
static int resize(uint32_t descriptor, uint64_t length) {
  uint64_t code;
  memcpy(&code, "SHMSIZ01", 8);
  return (int64_t)native(CONTROL, descriptor, code, (uintptr_t)&length, 8, 0,
                         0);
}
static uint64_t length(uint32_t descriptor) {
  uint64_t code, result = UINT64_MAX;
  memcpy(&code, "SHMLEN01", 8);
  if (native(CONTROL, descriptor, code, 0, 0, (uintptr_t)&result, 8) != 8)
    return UINT64_MAX;
  return result;
}
static uint32_t backing(uint64_t endpoint, uint32_t descriptor, int writable) {
  struct handles handles = {0};
  handles.count = 1;
  handles.entries[0].handle = descriptor;
  handles.entries[0].rights = writable ? RW_RIGHTS : RO_RIGHTS;
  int status = request(endpoint, BACKING, writable, &handles);
  if (status || handles.count != 1 ||
      handles.entries[0].rights != (MAP_RO_RIGHTS | (writable ? 2 : 0))) {
    fprintf(
        stderr, "named-shared-memory: backing status=%d count=%u rights=%llx\n",
        status, handles.count, (unsigned long long)handles.entries[0].rights);
    return 0;
  }
  return handles.entries[0].handle;
}
int main(void) {
  uint64_t key;
  memcpy(&key, "POSXCTRL", 8);
  uint64_t endpoint = native(CONTEXT_GET, key, 0, 0, 0, 0, 0);
  CHECK((int64_t)endpoint > 0);
  struct handles handles = {0};
  CHECK(request(endpoint, OPEN, 1 | 2 | 4, &handles) == 0 &&
        handles.count == 1);
  uint32_t first = handles.entries[0].handle;
  CHECK(handles.entries[0].rights == RW_RIGHTS &&
        native(RIGHTS, first, 0, 0, 0, 0, 0) == RW_RIGHTS);
  CHECK(length(first) == 0);
  CHECK(resize(first, 4097) == 0);
  uint32_t first_ram = backing(endpoint, first, 1);
  CHECK(first_ram != 0);
  CHECK((int64_t)native(RESIZE, first_ram, 0, 0, 0, 0, 0) == -13);
  uint64_t mapped = native(MAP, 0, 8192, 3, 2, first_ram, 0);
  CHECK((int64_t)mapped > 0);
  volatile unsigned char *bytes = (volatile unsigned char *)(uintptr_t)mapped;
  CHECK(bytes[0] == 0 && bytes[4096] == 0);
  bytes[0] = 17;
  bytes[4096] = 42;
  unsigned char byte = 0;
  CHECK(native(READ, first, (uintptr_t)&byte, 1, 0, 0, 0) == 1 && byte == 17);
  CHECK(native(SEEK, first, 0, SEEK_CURRENT, 0, 0, 0) == 1);
  CHECK(native(SEEK, first, 4096, SEEK_START, 0, 0, 0) == 4096);
  CHECK(native(READ, first, (uintptr_t)&byte, 1, 0, 0, 0) == 1 && byte == 42);
  memset(&handles, 0, sizeof(handles));
  CHECK(request(endpoint, OPEN, 0, &handles) == 0 && handles.count == 1);
  uint32_t reader = handles.entries[0].handle;
  CHECK(handles.entries[0].rights == RO_RIGHTS &&
        native(SAME, first, reader, 0, 0, 0, 0) == 0);
  CHECK(resize(reader, 0) == -9);
  uint32_t reader_ram = backing(endpoint, reader, 0);
  CHECK(reader_ram != 0 &&
        native(SAME, first_ram, reader_ram, 0, 0, 0, 0) == 1);
  CHECK(backing(endpoint, reader, 1) == 0);
  CHECK(native(SEEK, reader, 0, SEEK_CURRENT, 0, 0, 0) == 0);
  CHECK(native(READ, reader, (uintptr_t)&byte, 1, 0, 0, 0) == 1 && byte == 17);
  CHECK((int64_t)native(WRITE, reader, (uintptr_t)&byte, 1, 0, 0, 0) == -13);
  memset(&handles, 0, sizeof(handles));
  CHECK(request(endpoint, OPEN, 1 | 2 | 4, &handles) == -17 &&
        handles.count == 0);
  memset(&handles, 0, sizeof(handles));
  CHECK(request(endpoint, OPEN, 1 | 8, &handles) == 0 && handles.count == 1);
  uint32_t truncated = handles.entries[0].handle;
  CHECK(native(SAME, first, truncated, 0, 0, 0, 0) == 0 && length(first) == 0);
  CHECK(native(CLOSE, truncated, 0, 0, 0, 0, 0) == 0);
  CHECK(resize(first, 4097) == 0 && bytes[0] == 0 && bytes[4096] == 0);
  bytes[0] = 51;
  memset(&handles, 0, sizeof(handles));
  CHECK(request(endpoint, UNLINK, 0, &handles) == 0 && handles.count == 0);
  CHECK(bytes[0] == 51 && length(reader) == 4097);
  memset(&handles, 0, sizeof(handles));
  CHECK(request(endpoint, OPEN, 0, &handles) == -2 && handles.count == 0);
  memset(&handles, 0, sizeof(handles));
  CHECK(request(endpoint, OPEN, 1 | 2 | 4, &handles) == 0 &&
        handles.count == 1);
  uint32_t fresh = handles.entries[0].handle;
  CHECK(native(SAME, first, fresh, 0, 0, 0, 0) == 0 && length(fresh) == 0);
  CHECK(resize(fresh, 4097) == 0);
  uint32_t fresh_ram = backing(endpoint, fresh, 1);
  CHECK(fresh_ram != 0 && native(SAME, first_ram, fresh_ram, 0, 0, 0, 0) == 0);
  uint64_t fresh_map = native(MAP, 0, 8192, 3, 2, fresh_ram, 0);
  CHECK((int64_t)fresh_map > 0);
  CHECK(*(volatile unsigned char *)(uintptr_t)fresh_map == 0 && bytes[0] == 51);
  memset(&handles, 0, sizeof(handles));
  CHECK(request(endpoint, UNLINK, 0, &handles) == 0);
  CHECK(native(CLOSE, first, 0, 0, 0, 0, 0) == 0 &&
        native(CLOSE, reader, 0, 0, 0, 0, 0) == 0);
  CHECK(native(CLOSE, fresh, 0, 0, 0, 0, 0) == 0);
  CHECK(native(CLOSE, first_ram, 0, 0, 0, 0, 0) == 0 &&
        native(CLOSE, reader_ram, 0, 0, 0, 0, 0) == 0 &&
        native(CLOSE, fresh_ram, 0, 0, 0, 0, 0) == 0);
  CHECK(bytes[0] == 51 && *(volatile unsigned char *)(uintptr_t)fresh_map == 0);
  CHECK(native(UNMAP, mapped, 8192, 0, 0, 0, 0) == 0 &&
        native(UNMAP, fresh_map, 8192, 0, 0, 0, 0) == 0);
  fprintf(
      stderr,
      "named-shared-memory: PASS authenticated IPC, zero creation, access "
      "attenuation, truncate, unlink lifetime and independent recreation\n");
  return 0;
}
