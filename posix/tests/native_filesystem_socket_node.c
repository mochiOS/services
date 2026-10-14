#include <stdint.h>

struct header {
  char magic[4];
  uint16_t version, opcode;
  uint64_t request, mount, node, open, offset;
  uint32_t length, flags;
  int32_t status;
  uint32_t mode;
};
struct attachment {
  uint32_t handle, reserved;
  uint64_t rights;
};
struct handles {
  uint32_t count, flags;
  struct attachment entries[4];
};
struct request {
  struct header header;
  uint32_t uid, gid, groups;
  char path[32];
};
struct response {
  struct header header;
  unsigned char data[112];
};
_Static_assert(sizeof(struct header) == 64, "filesystem header");
_Static_assert(sizeof(struct handles) == 72, "IPC attachments");

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
static void log_message(const char *bytes) {
  uint64_t length = 0;
  while (bytes[length])
    ++length;
  native(660, (uintptr_t)bytes, length, 0, 0, 0, 0);
}
__attribute__((noreturn)) static void finish(int status) {
  native(574, status, 0, 0, 0, 0, 0);
  for (;;)
    __asm__ volatile("pause");
}
#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      log_message("filesystem-socket-ipc: FAIL " #condition "\n");             \
      finish(1);                                                               \
    }                                                                          \
  } while (0)

static int request(uint64_t endpoint, uint16_t opcode, int legacy,
                   struct response *response) {
  static const char path[] = "/native-socket-ipc-test";
  struct request request = {0};
  request.header =
      (struct header){{'M', 'F', 'S', '1'},  1, opcode, 142, 0, 0, 0, 0,
                      12 + sizeof(path) - 1, 0, 0,      0600};
  for (unsigned index = 0; index < sizeof(path) - 1; ++index)
    request.path[index] = path[index];
  struct handles handles = {0};
  uint64_t result = native(legacy ? 588 : 632, endpoint, (uintptr_t)&request,
                           64 + request.header.length, (uintptr_t)response,
                           sizeof(*response), legacy ? 0 : (uintptr_t)&handles);
  CHECK((int64_t)result >= 0);
  CHECK((uint32_t)result >= 64 &&
        (uint32_t)result == 64 + response->header.length);
  CHECK(response->header.request == 142 && response->header.opcode == 0x8000);
  CHECK(response->header.magic[0] == 'M' && response->header.magic[1] == 'F' &&
        response->header.magic[2] == 'S' && response->header.magic[3] == '1');
  CHECK(response->header.version == 1 && handles.count == 0 &&
        handles.flags == 0);
  return response->header.status;
}
static uint32_t read32(const unsigned char *bytes) {
  return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 |
         (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}
__attribute__((used, noreturn)) void filesystem_socket_main(void) {
  uint64_t endpoint = native(628, UINT64_C(0x4c5254433153464d), 0, 0, 0, 0, 0);
  CHECK((int64_t)endpoint > 0);
  static const char name[] = "filesystem.service";
  uint64_t global = native(518, (uintptr_t)name, sizeof(name) - 1, 0, 0, 0, 0);
  CHECK((int64_t)global > 0);
  struct response response;
  // The exact same uid-zero envelope is not authority through ordinary IPC.
  CHECK(request(global, 38, 1, &response) == -13);
  int result = request(endpoint, 28, 0, &response);
  CHECK(result == 0 || result == -2);
  CHECK(request(endpoint, 38, 0, &response) == 0 &&
        response.header.length == 112);
  CHECK(read32(response.data + 36) == 5 && read32(response.data + 40) == 0600);
  CHECK(read32(response.data + 44) == 0 && read32(response.data + 48) == 0);
  CHECK(read32(response.data + 52) == 1);
  CHECK(request(endpoint, 38, 0, &response) == -17);
  CHECK(request(endpoint, 19, 0, &response) == 0 &&
        read32(response.data + 36) == 5);
  CHECK(request(endpoint, 28, 0, &response) == 0);
  CHECK(request(endpoint, 19, 0, &response) == -2);
  log_message("filesystem-socket-ipc: PASS delegated control, denied global "
              "IPC, exclusive socket inode and unlink\n");
  finish(0);
}
__attribute__((naked, noreturn)) void filesystem_socket_entry(void) {
  __asm__ volatile("andq $-16, %rsp\ncall filesystem_socket_main\nud2");
}
int main(void) { filesystem_socket_main(); }
