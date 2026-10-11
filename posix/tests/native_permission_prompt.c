/* Isolated native boundary test. Launches the real secure-ui executable and
 * checks denial without opening a GUI or bypassing production authorization. */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

enum {
  IPC_CREATE = 587,
  IPC_CALL = 588,
  FIND_PROCESS = 518,
  HANDLE_CLOSE = 626,
  LAUNCH_HANDLE_GET = 628,
  IPC_RECV_HANDLES = 631,
  IPC_CALL_HANDLES = 632,
  PROCESS_STATUS = 642,
  PROCESS_RESUME = 645,
  PROCESS_CREATE = 676
};
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
#define N(number, a, b, c)                                                     \
  native6(number, (uint64_t)(a), (uint64_t)(b), (uint64_t)(c), 0, 0, 0)
#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "permission-native: FAIL line %d errno %d\n", __LINE__,  \
              errno);                                                          \
      return 1;                                                                \
    }                                                                          \
  } while (0)
struct attachment {
  uint32_t handle, reserved;
  uint64_t rights;
};
struct attachments {
  uint32_t count, reserved;
  struct attachment entries[4];
};
struct process_status {
  uint64_t process;
  uint32_t state, reserved;
  uint64_t exit_code;
};
static uint32_t get32(const void *p) {
  uint32_t v;
  memcpy(&v, p, 4);
  return v;
}
static uint64_t get64(const void *p) {
  uint64_t v;
  memcpy(&v, p, 8);
  return v;
}
static void put32(void *p, uint32_t v) { memcpy(p, &v, 4); }
static void put64(void *p, uint64_t v) { memcpy(p, &v, 8); }
static const char image_path[] = "/system/services/secure-ui.service";
static void pause_tick(void) {
  const struct timespec delay = {0, 10000000};
  nanosleep(&delay, 0);
}

static int credential_child(void) {
  gid_t groups[4] = {777, 777, 777, 777};
  CHECK(getuid() == 505 && geteuid() == 505);
  CHECK(getgid() == 24 && getegid() == 24);
  CHECK(getgroups(4, groups) == 2 && groups[0] == 10 && groups[1] == 20);
  CHECK(groups[2] == 777 && groups[3] == 777);
  CHECK(umask(027) == 022);
  errno = 0;
  CHECK(setuid(0) == -1 && errno == EPERM);
  errno = 0;
  CHECK(setgid(0) == -1 && errno == EPERM);
  CHECK(getuid() == 505 && getgid() == 24);
  fprintf(stderr, "fresh-spawn: child PASS newlib uid/gid/groups/umask and "
                  "elevation denial\n");
  return 37;
}

static int fresh_spawn(int64_t posix, int64_t authority) {
  const gid_t parent_groups[2] = {30, 40};
  gid_t observed[4] = {777, 777, 777, 777};
  CHECK(setgroups(2, parent_groups) == 0);
  CHECK(getgroups(0, NULL) == 2);
  CHECK(getgroups(4, observed) == 2 && observed[0] == 30 && observed[1] == 40);
  CHECK(observed[2] == 777 && observed[3] == 777);
  const char path[] = "/system/services/input.service";
  unsigned char metadata[20000], request[48 + sizeof(path) - 1] = {0},
                                                             reply[2048];
  int fd = open("/system/resources/native-spawn-metadata.bin", O_RDONLY);
  CHECK(fd >= 0);
  ssize_t length = read(fd, metadata, sizeof(metadata));
  CHECK(length > 0 && close(fd) == 0);
  size_t grants =
      32 + get32(metadata + 8) + get32(metadata + 24) + get32(metadata + 12);
  CHECK(grants + 24 <= (size_t)length &&
        get64(metadata + grants) == get64("POSXCTRL"));
  put32(metadata + grants + 8, (uint32_t)posix);
  memcpy(request, "POSX", 4);
  request[4] = 1;
  request[6] = 5;
  put64(request + 8, 2);
  put32(request + 20, sizeof(request) - 32);
  put32(request + 36, 1);
  put32(request + 44, sizeof(path) - 1);
  memcpy(request + 48, path, sizeof(path) - 1);
  struct attachments handles = {0};
  int64_t message =
      native6(IPC_CALL_HANDLES, posix, (uint64_t)request, sizeof(request),
              (uint64_t)reply, sizeof(reply), (uint64_t)&handles);
  CHECK(message >= 0 && (uint32_t)message == 32 && get32(reply + 24) == 0 &&
        handles.count == 1);
  uint32_t image = handles.entries[0].handle;
  unsigned char authorization[12 + sizeof(path) - 1] = {0};
  put32(authorization, 0x43414553);
  put64(authorization + 4, 2);
  memcpy(authorization + 12, path, sizeof(path) - 1);
  message = native6(IPC_CALL, authority, (uint64_t)authorization,
                    sizeof(authorization), (uint64_t)reply, sizeof(reply), 0);
  CHECK(message >= 0 && get64(reply) == 0);
  int64_t process = N(PROCESS_CREATE, image, metadata, length);
  CHECK(process > 0);
  unsigned char registration[52] = {0};
  memcpy(registration, "POSX", 4);
  registration[4] = 1;
  registration[6] = 54; /* OP_PROCESS_SPAWNED; no PID is serialized. */
  put64(registration + 8, 3);
  put32(registration + 20, 20);
  put32(registration + 32, 505);
  put32(registration + 36, 24);
  put32(registration + 40, 2);
  put32(registration + 44, 10);
  put32(registration + 48, 20);
  memset(&handles, 0, sizeof(handles));
  handles.count = 1;
  handles.entries[0].handle = (uint32_t)process;
  handles.entries[0].rights = 16 | 32; /* WAIT | SIGNAL only. */
  message = native6(IPC_CALL_HANDLES, posix, (uint64_t)registration,
                    sizeof(registration), (uint64_t)reply, sizeof(reply),
                    (uint64_t)&handles);
  fprintf(stderr, "fresh-spawn: registration status %d\n",
          (int32_t)get32(reply + 24));
  CHECK(message >= 0 && (uint32_t)message == 32 && get32(reply + 24) == 0 &&
        handles.count == 0);
  unsigned char inspection[32] = {0};
  memcpy(inspection, "POSX", 4);
  inspection[4] = 1;
  inspection[6] = 55; /* OP_PROCESS_SESSION_INFO; WAIT-only object, no PID. */
  put64(inspection + 8, 4);
  memset(&handles, 0, sizeof(handles));
  handles.count = 1;
  handles.entries[0].handle = (uint32_t)process;
  handles.entries[0].rights = 16;
  message =
      native6(IPC_CALL_HANDLES, posix, (uint64_t)inspection, sizeof(inspection),
              (uint64_t)reply, sizeof(reply), (uint64_t)&handles);
  CHECK(message >= 0 && (uint32_t)message == 52 && get32(reply + 24) == 0 &&
        handles.count == 0);
  CHECK(get32(reply + 32) == 505 && get32(reply + 36) == 505 &&
        get32(reply + 40) == 24 && get32(reply + 44) == 24);
  memset(&handles, 0, sizeof(handles));
  handles.count = 1;
  handles.entries[0].handle = (uint32_t)process;
  handles.entries[0].rights = 16 | 32; /* Inspection must not accept SIGNAL. */
  message =
      native6(IPC_CALL_HANDLES, posix, (uint64_t)inspection, sizeof(inspection),
              (uint64_t)reply, sizeof(reply), (uint64_t)&handles);
  CHECK(message >= 0 && (uint32_t)message == 32 &&
        (int32_t)get32(reply + 24) == -22 && handles.count == 0);
  CHECK(N(PROCESS_RESUME, process, 0, 0) == 0);
  struct process_status status = {0};
  for (unsigned attempt = 0; attempt < 500; ++attempt) {
    CHECK(N(PROCESS_STATUS, process, &status, 0) == 0);
    if (status.state == 2)
      break;
    pause_tick();
  }
  CHECK(status.state == 2 && status.exit_code == 37);
  CHECK(N(HANDLE_CLOSE, process, 0, 0) == 0 &&
        N(HANDLE_CLOSE, image, 0, 0) == 0);
  fprintf(
      stderr,
      "fresh-spawn: PASS stopped creation, attached registration, "
      "WAIT-only inspection, newlib credentials, resume and retained exit\n");
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--credential-child") == 0)
    return credential_child();
  fprintf(stderr, "permission-native: start real secure-ui endpoint test\n");
  unsigned char metadata[20000];
  int fd = open("/system/resources/native-permission-metadata.bin", O_RDONLY);
  CHECK(fd >= 0);
  ssize_t length = read(fd, metadata, sizeof(metadata));
  CHECK(length > 0 && close(fd) == 0 && memcmp(metadata, "MCRT", 4) == 0);
  int64_t posix = N(LAUNCH_HANDLE_GET, get64("POSXCTRL"), 0, 0);
  int64_t ready = N(IPC_CREATE, 0, 0, 0);
  CHECK(posix > 0 && ready > 0);
  const char placeholder[] = "--service-ready=00000000000000000000:123";
  int patched = 0;
  for (size_t i = 0; i + sizeof(placeholder) <= (size_t)length; ++i) {
    if (memcmp(metadata + i, placeholder, sizeof(placeholder)) == 0) {
      char decimal[21];
      CHECK(snprintf(decimal, sizeof(decimal), "%020llu",
                     (unsigned long long)ready) == 20);
      memcpy(metadata + i + 16, decimal, 20);
      patched++;
    }
  }
  CHECK(patched == 1);
  size_t grants =
      32 + get32(metadata + 8) + get32(metadata + 24) + get32(metadata + 12);
  CHECK(grants + 24 <= (size_t)length &&
        get64(metadata + grants) == get64("POSXCTRL"));
  put32(metadata + grants + 8, (uint32_t)posix);

  unsigned char request[48 + sizeof(image_path) - 1] = {0}, reply[2048] = {0};
  memcpy(request, "POSX", 4);
  request[4] = 1;
  request[6] = 5;
  put64(request + 8, 1);
  put32(request + 20, sizeof(request) - 32);
  put32(request + 36, 1);
  put32(request + 44, sizeof(image_path) - 1);
  memcpy(request + 48, image_path, sizeof(image_path) - 1);
  struct attachments handles = {0};
  int64_t message =
      native6(IPC_CALL_HANDLES, posix, (uint64_t)request, sizeof(request),
              (uint64_t)reply, sizeof(reply), (uint64_t)&handles);
  CHECK(message >= 0 && (uint32_t)message == 32 && get32(reply + 24) == 0);
  CHECK(handles.count == 1 && handles.entries[0].handle);
  uint32_t image = handles.entries[0].handle;
  int64_t authority =
      N(FIND_PROCESS, "capability.service", strlen("capability.service"), 0);
  CHECK(authority > 0);
  for (unsigned scenario = 0; scenario < 2; ++scenario) {
    unsigned char authorization[12 + sizeof(image_path) - 1] = {0};
    put32(authorization, 0x43414553);
    put64(authorization + 4, 2);
    memcpy(authorization + 12, image_path, sizeof(image_path) - 1);
    message = native6(IPC_CALL, authority, (uint64_t)authorization,
                      sizeof(authorization), (uint64_t)reply, sizeof(reply), 0);
    CHECK(message >= 0 && (uint32_t)message >= 16 && get64(reply) == 0);
    int64_t process = N(PROCESS_CREATE, image, metadata, length);
    CHECK(process > 0 && N(PROCESS_RESUME, process, 0, 0) == 0);
    int received = 0;
    for (unsigned attempt = 0; attempt < 1000; ++attempt) {
      memset(&handles, 0, sizeof(handles));
      message = native6(IPC_RECV_HANDLES, (uint64_t)reply, sizeof(reply),
                        (uint64_t)&handles, 0, 0, 0);
      if (message >= 0) {
        received = 1;
        break;
      }
      CHECK(message == -11); /* Native EAGAIN, not newlib's errno ABI. */
      pause_tick();
    }
    CHECK(received && (uint32_t)message == 20 && get32(reply) == 0x59524453);
    CHECK(reply[6] == 3 && get64(reply + 8) == 123 && get32(reply + 16) == 0);
    CHECK(handles.count == 1 && handles.entries[0].handle);
    CHECK((handles.entries[0].rights & 8) ==
          0); /* RECEIVE never leaves child. */
    uint32_t destination = handles.entries[0].handle;
    unsigned char prompt[25] = {0};
    memcpy(prompt, "MPRMPT01", 8);
    prompt[8] = 1;
    prompt[10] = 1;
    prompt[24] = 'x';
    put64(prompt + 16, scenario == 0 ? 124 : 123);
    memset(&handles, 0, sizeof(handles));
    if (scenario == 1) {
      handles.count = 1;
      handles.entries[0].handle = image;
      handles.entries[0].rights =
          1; /* Unexpected READ-only image attachment. */
    }
    message =
        native6(IPC_CALL_HANDLES, destination, (uint64_t)prompt, sizeof(prompt),
                (uint64_t)reply, sizeof(reply), (uint64_t)&handles);
    fprintf(stderr,
            "permission-native: scenario %u reply result %lld length %u status "
            "%u handles %u\n",
            scenario, (long long)message, (uint32_t)message, get32(reply),
            handles.count);
    CHECK(message >= 0 && (uint32_t)message == 4 &&
          (int32_t)get32(reply) == -13 && handles.count == 0);
    struct process_status status = {0};
    for (unsigned attempt = 0; attempt < 500; ++attempt) {
      CHECK(N(PROCESS_STATUS, process, &status, 0) == 0);
      if (status.state == 2)
        break;
      pause_tick();
    }
    CHECK(status.state == 2 && status.exit_code == 0);
    CHECK(N(HANDLE_CLOSE, destination, 0, 0) == 0 &&
          N(HANDLE_CLOSE, process, 0, 0) == 0);
  }
  CHECK(N(HANDLE_CLOSE, image, 0, 0) == 0);
  fprintf(stderr,
          "permission-native: PASS real secure-ui native creation, SEND-only "
          "publication, token/attachment denial, reply and exit\n");
  return fresh_spawn(posix, authority);
}
