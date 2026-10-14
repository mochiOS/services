#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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
struct wait_item {
  uint32_t handle, minimum;
  uint64_t interests, observed;
};
_Static_assert(sizeof(struct header) == 32, "POSIX header");
_Static_assert(sizeof(struct handles) == 72, "native attachments");
_Static_assert(sizeof(struct wait_item) == 24, "native wait");
#define RIGHTS (UINT64_C(275) | (UINT64_C(3) << 62))
#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "native-socket-pair: FAIL line=%u condition=%s\n",       \
              __LINE__, #condition);                                           \
      return 1;                                                                \
    }                                                                          \
  } while (0)
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
static int create(uint64_t endpoint, uint16_t domain, uint16_t kind,
                  uint32_t options, struct handles *handles) {
  unsigned char bytes[48] = {0};
  struct header header = {{'P', 'O', 'S', 'X'}, 1, 80, 123, 0, 16, 0, 0};
  memcpy(bytes, &header, 32);
  memcpy(bytes + 32, &domain, 2);
  memcpy(bytes + 34, &kind, 2);
  memcpy(bytes + 40, &options, 4);
  struct header response = {0};
  uint64_t result =
      native(632, endpoint, (uintptr_t)bytes, sizeof(bytes),
             (uintptr_t)&response, sizeof(response), (uintptr_t)handles);
  if ((int64_t)result < 0)
    return (int64_t)result;
  if ((uint32_t)result != 32 || memcmp(response.magic, "POSX", 4) ||
      response.version != 1 || response.opcode != 0x8000 ||
      response.request != 123 || response.flags || response.length ||
      response.reserved || handles->flags)
    return -999;
  return response.status;
}
static int control(uint32_t handle, const char *tag, const void *input,
                   uint64_t input_length, void *output,
                   uint64_t output_length) {
  uint64_t code;
  memcpy(&code, tag, 8);
  return (int64_t)native(668, handle, code, (uintptr_t)input, input_length,
                         (uintptr_t)output, output_length);
}
static int wait_ready(uint32_t handle, uint64_t interests, uint64_t *observed) {
  struct wait_item item = {handle, 0, interests, 0};
  int result = (int64_t)native(647, (uintptr_t)&item, 1, 0, 0, 0, 0);
  *observed = item.observed;
  return result;
}
int main(void) {
  uint64_t key;
  memcpy(&key, "POSXCTRL", 8);
  uint64_t endpoint = native(628, key, 0, 0, 0, 0, 0);
  CHECK((int64_t)endpoint > 0);
  struct handles handles = {0};
  CHECK(create(endpoint, 2, 1, 0, &handles) == -95 && handles.count == 0);
  CHECK(create(endpoint, 1, 3, 0, &handles) == -95 && handles.count == 0);
  CHECK(create(endpoint, 1, 1, 2, &handles) == -22 && handles.count == 0);
  CHECK(create(endpoint, 1, 1, 1, &handles) == 0 && handles.count == 2);
  uint32_t a = handles.entries[0].handle, b = handles.entries[1].handle;
  CHECK(handles.entries[0].rights == RIGHTS &&
        handles.entries[1].rights == RIGHTS);
  CHECK(native(664, a, 0, 0, 0, 0, 0) == RIGHTS);
  CHECK(native(666, a, b, 0, 0, 0, 0) == 0);
  uint64_t observed;
  CHECK(wait_ready(a, 4, &observed) == 0 && observed == 4);
  char bytes[16] = {0};
  CHECK((int64_t)native(634, b, (uintptr_t)bytes, 1, 0, 0, 0) == -11);
  CHECK(native(635, a, (uintptr_t) "hello", 5, 0, 0, 0) == 5);
  CHECK(wait_ready(b, 2, &observed) == 0 && observed == 2);
  // Inspection needs READ only, not SEEK or CONTROL. Attenuated aliases still
  // refer to the same receive queue, and denied attempts cannot consume it.
  uint64_t reader = native(627, b, 1, 0, 0, 0, 0);
  uint64_t writer = native(627, b, 2, 0, 0, 0, 0);
  CHECK((int64_t)reader > 0 && (int64_t)writer > 0);
  CHECK(native(664, reader, 0, 0, 0, 0, 0) == 1);
  CHECK((int64_t)native(673, writer, (uintptr_t)bytes, 3, 0, 0, 0) == -13);
  CHECK((int64_t)native(636, reader, 0, 0, 0, 0, 0) == -13);
  CHECK((int64_t)control(reader, "SOPRDY01", 0, 0, &observed, 8) == -13);
  for (unsigned repeat = 0; repeat < 3; ++repeat) {
    memset(bytes, 0x55, sizeof(bytes));
    CHECK(native(673, reader, (uintptr_t)bytes, 3, 2, 0, 0) == 3);
    CHECK(!memcmp(bytes, "llo", 3) && bytes[3] == 0x55);
    CHECK(wait_ready(b, 2, &observed) == 0 && observed == 2);
  }
  CHECK((int64_t)native(673, reader, 0, 3, 0, 0, 0) == -14);
  CHECK(native(673, reader, (uintptr_t)bytes, sizeof(bytes), 0, 0, 0) == 5);
  CHECK(!memcmp(bytes, "hello", 5));
  CHECK((int64_t)native(673, reader, (uintptr_t)bytes, 1, 5, 0, 0) == -11);
  CHECK(native(626, reader, 0, 0, 0, 0, 0) == 0);
  CHECK(native(626, writer, 0, 0, 0, 0, 0) == 0);
  puts("native-socket-pair: READ-only queue inspection preserves bytes PASS");
  CHECK(native(635, b, (uintptr_t) "reply", 5, 0, 0, 0) == 5);
  CHECK(native(634, a, (uintptr_t)bytes, 5, 0, 0, 0) == 5 &&
        !memcmp(bytes, "reply", 5));
  uint32_t options;
  CHECK(control(a, "SOPOGT01", 0, 0, &options, 4) == 4 && options == 1);
  uint64_t alias = native(627, a, RIGHTS, 0, 0, 0, 0);
  CHECK((int64_t)alias > 0 && native(666, a, alias, 0, 0, 0, 0) == 1);
  options = 0;
  CHECK(control(alias, "SOPOST01", &options, 4, 0, 0) == 0);
  CHECK(control(a, "SOPOGT01", 0, 0, &options, 4) == 4 && options == 0);
  CHECK(control(b, "SOPOGT01", 0, 0, &options, 4) == 4 && options == 1);
  uint32_t how = 1;
  CHECK(control(alias, "SOPSHD01", &how, 4, 0, 0) == 0);
  CHECK((int64_t)native(635, a, (uintptr_t) "x", 1, 0, 0, 0) == -32);
  CHECK(control(b, "SOPRDY01", 0, 0, &options, 4) == 4 && options == 7);
  CHECK(native(634, b, (uintptr_t)bytes, 3, 0, 0, 0) == 3 &&
        !memcmp(bytes, "hel", 3));
  CHECK(native(634, b, (uintptr_t)bytes, 8, 0, 0, 0) == 2 &&
        !memcmp(bytes, "lo", 2));
  CHECK(native(634, b, (uintptr_t)bytes, 1, 0, 0, 0) == 0);
  CHECK(native(635, b, (uintptr_t) "last", 4, 0, 0, 0) == 4);
  CHECK(native(626, a, 0, 0, 0, 0, 0) == 0);
  CHECK(native(634, alias, (uintptr_t)bytes, 4, 0, 0, 0) == 4 &&
        !memcmp(bytes, "last", 4));
  CHECK(native(626, alias, 0, 0, 0, 0, 0) == 0);
  // Final-reference release is delivered asynchronously. Synchronize through
  // subsequent Provider operations, allowing scheduler progress, never sleep.
  for (unsigned attempt = 0; attempt < 1000; ++attempt) {
    CHECK(control(b, "SOPRDY01", 0, 0, &options, 4) == 4);
    if (options == 29)
      break;
    native(579, 0, 0, 0, 0, 0, 0);
  }
  CHECK(options == 29);
  CHECK((int64_t)native(635, b, (uintptr_t) "x", 1, 0, 0, 0) == -32);
  CHECK(wait_ready(b, 14, &observed) == 0 && observed == 14);
  CHECK(native(626, b, 0, 0, 0, 0, 0) == 0);
  // Native indexed inspection does not make a socket a POSIX seekable file.
  int descriptors[2];
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, descriptors) == 0);
  CHECK(send(descriptors[0], "data", 4, 0) == 4);
  CHECK(pread(descriptors[1], bytes, 4, 0) == -1 && errno == ESPIPE);
  CHECK(recv(descriptors[1], bytes, 4, 0) == 4 && !memcmp(bytes, "data", 4));
  CHECK(close(descriptors[0]) == 0 && close(descriptors[1]) == 0);
  puts("native-socket-pair: POSIX pread remains ESPIPE without consuming data PASS");
  puts("native-socket-pair: PASS");
  return 0;
}
