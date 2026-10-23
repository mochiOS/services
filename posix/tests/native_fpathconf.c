#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern int mochi_fd_from_file_handle(uint32_t, int);
struct handle_info {
  uint32_t handle, reserved;
  uint64_t rights;
};
static struct handle_info before[256], after[256];
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "fpathconf: FAIL line=%u errno=%d: %s\n", __LINE__,      \
              errno, #x);                                                      \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static int64_t native(uint64_t number, uint64_t a, uint64_t b, uint64_t c) {
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(a), "S"(b), "d"(c)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
static int count(struct handle_info *items) {
  return (int)native(680, (uintptr_t)items, 256, 0);
}
int main(void) {
  alarm(60);
  char path[96];
  snprintf(path, sizeof(path), "/tmp/native-fpathconf-%ld", (long)getpid());
  int warm = open(path, O_CREAT | O_RDWR, 0600);
  CHECK(warm >= 0 && fpathconf(warm, _PC_NAME_MAX) == 255 && close(warm) == 0);
  int baseline = count(before);
  CHECK(baseline > 0 && baseline < 256);
  int fd = open(path, O_RDWR);
  CHECK(fd >= 0);
  int total = count(after);
  CHECK(total == baseline + 1);
  uint32_t source = 0;
  for (int i = 0; i < total; ++i) {
    int found = 0;
    for (int j = 0; j < baseline; ++j)
      found |= before[j].handle == after[i].handle;
    if (!found) {
      CHECK(source == 0);
      source = after[i].handle;
    }
  }
  CHECK(source != 0);
  int directory = open("/", O_RDONLY | O_DIRECTORY);
  CHECK(directory >= 0);
  errno = 73;
  CHECK(fpathconf(fd, _PC_NAME_MAX) == 255 && errno == 73);
  CHECK(fpathconf(fd, _PC_LINK_MAX) == 65535 && errno == 73);
  CHECK(fpathconf(directory, _PC_PATH_MAX) == 4097 && errno == 73);
  CHECK(close(directory) == 0);
  for (int mode = O_RDONLY; mode <= O_WRONLY; ++mode) {
    int access = open(path, mode);
    CHECK(access >= 0);
    errno = 74;
    CHECK(fpathconf(access, _PC_NAME_MAX) == 255 && errno == 74);
    CHECK(close(access) == 0);
  }
  fprintf(stderr,
          "fpathconf: PASS real owner values, access modes and errno\n");

  int64_t narrowed = native(627, source, 1ULL | (1ULL << 62) | (1ULL << 63), 0);
  CHECK(narrowed > 0);
  int readonly = mochi_fd_from_file_handle((uint32_t)narrowed, O_CLOEXEC);
  CHECK(readonly >= 0 && native(626, (uint64_t)narrowed, 0, 0) == 0);
  errno = 75;
  CHECK(fpathconf(readonly, _PC_NAME_MAX) == 255 && errno == 75);
  CHECK(close(readonly) == 0);
  fprintf(stderr,
          "fpathconf: PASS READ-only attenuated Handle needs no CONTROL\n");

  int ends[2];
  CHECK(pipe(ends) == 0);
  errno = 76;
  CHECK(fpathconf(ends[0], _PC_PIPE_BUF) == 512 && errno == 76);
  CHECK(fpathconf(ends[1], _PC_PIPE_BUF) == 512 && errno == 76);
  CHECK(fpathconf(ends[0], _PC_NAME_MAX) == -1 && errno == ENOTSUP);
  CHECK(close(ends[0]) == 0 && close(ends[1]) == 0);
  CHECK(fpathconf(-1, _PC_NAME_MAX) == -1 && errno == EBADF);
  CHECK(fpathconf(fd, -1) == -1 && errno == EINVAL);
  CHECK(fpathconf(fd, _PC_FILESIZEBITS) == -1 && errno == ENOTSUP);
  int device = open("/dev/null", O_RDONLY);
  CHECK(device >= 0);
  CHECK(fpathconf(device, _PC_NAME_MAX) == -1 && errno == ENOTSUP);
  CHECK(close(device) == 0);
  fprintf(
      stderr,
      "fpathconf: PASS pipe guarantee and explicit unsupported/error cases\n");

  CHECK(write(fd, "data", 4) == 4 && lseek(fd, 1, SEEK_SET) == 1);
  int alias = dup(fd);
  CHECK(alias >= 0 && unlink(path) == 0);
  errno = 77;
  CHECK(fpathconf(alias, _PC_NAME_MAX) == 255 && errno == 77);
  CHECK(lseek(alias, 0, SEEK_CUR) == 1);
  CHECK(close(fd) == 0 && fpathconf(alias, _PC_LINK_MAX) == 65535);
  CHECK(close(alias) == 0);
  CHECK(fpathconf(alias, _PC_NAME_MAX) == -1 && errno == EBADF);
  CHECK(count(after) == baseline);
  fprintf(stderr, "fpathconf: PASS unlinked/duplicated FD identity, cursor and "
                  "Handle recovery\n");
  return 0;
}
