#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "pathconf: FAIL line=%u errno=%d: %s\n", __LINE__,       \
              errno, #x);                                                      \
      return 1;                                                                \
    }                                                                          \
  } while (0)
struct handle_info {
  uint32_t handle, reserved;
  uint64_t rights;
};
static struct handle_info snapshot[256];
static int count(void) {
  uint64_t n = 680;
  __asm__ volatile("syscall"
                   : "+a"(n)
                   : "D"((uintptr_t)snapshot), "S"(256ULL), "d"(0ULL)
                   : "rcx", "r11", "memory");
  return (int)n;
}
static int permissions(const char *file, const char *hidden) {
  CHECK(setgid(20) == 0 && setuid(501) == 0);
  CHECK(open(file, O_RDONLY) == -1 && errno == EACCES);
  errno = 83;
  CHECK(pathconf(file, _PC_NAME_MAX) == 255 && errno == 83);
  CHECK(pathconf(hidden, _PC_NAME_MAX) == -1 && errno == EACCES);
  return 0;
}
static int confinement(const char *root) {
  CHECK(chroot(root) == 0 && chdir("/") == 0);
  CHECK(pathconf("file", _PC_NAME_MAX) == 255);
  CHECK(pathconf("/../tmp", _PC_NAME_MAX) == -1 && errno == ENOENT);
  CHECK(pathconf("/escape", _PC_NAME_MAX) == -1 && errno == ENOENT);
  return 0;
}
int main(void) {
  alarm(60);
  char root[96], file[128], alias[128], dangling[128], hidden[128],
      hidden_file[160], escape[128], slash[132];
  snprintf(root, sizeof(root), "/tmp/native-pathconf-%ld", (long)getpid());
  snprintf(file, sizeof(file), "%s/file", root);
  snprintf(alias, sizeof(alias), "%s/alias", root);
  snprintf(dangling, sizeof(dangling), "%s/dangling", root);
  snprintf(hidden, sizeof(hidden), "%s/hidden", root);
  snprintf(hidden_file, sizeof(hidden_file), "%s/file", hidden);
  snprintf(escape, sizeof(escape), "%s/escape", root);
  snprintf(slash, sizeof(slash), "%s/", alias);
  CHECK(mkdir(root, 0755) == 0 && mkdir(hidden, 0700) == 0);
  int fd = open(file, O_CREAT | O_RDWR, 0000);
  CHECK(fd >= 0 && write(fd, "data", 4) == 4 && close(fd) == 0);
  fd = open(hidden_file, O_CREAT | O_RDWR, 0000);
  CHECK(fd >= 0 && close(fd) == 0);
  errno = 81;
  CHECK(pathconf(file, _PC_NAME_MAX) == 255 && errno == 81);
  CHECK(pathconf(file, _PC_LINK_MAX) == 65535 && errno == 81);
  CHECK(pathconf(root, _PC_PATH_MAX) == 4097 && errno == 81);
  CHECK(symlink("file", alias) == 0 && symlink("missing", dangling) == 0 &&
        symlink("/tmp", escape) == 0);
  CHECK(pathconf(alias, _PC_NAME_MAX) == 255);
  CHECK(pathconf(dangling, _PC_NAME_MAX) == -1 && errno == ENOENT);
  CHECK(pathconf(slash, _PC_NAME_MAX) == -1 && errno == ENOTDIR);
  fprintf(stderr,
          "pathconf: PASS owner limits, symlinks and trailing separator\n");

  CHECK(pathconf(NULL, _PC_NAME_MAX) == -1 && errno == EFAULT);
  CHECK(pathconf((const char *)1, _PC_NAME_MAX) == -1 && errno == EFAULT);
  CHECK(pathconf("", _PC_NAME_MAX) == -1 && errno == ENOENT);
  CHECK(pathconf(file, -1) == -1 && errno == EINVAL);
  CHECK(pathconf(file, _PC_PIPE_BUF) == -1 && errno == ENOTSUP);
  fprintf(
      stderr,
      "pathconf: PASS checked caller memory and explicit selector errors\n");

  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0)
    _exit(permissions(file, hidden_file));
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  fprintf(stderr, "pathconf: PASS no target read permission needed; parent "
                  "search enforced\n");
  child = fork();
  CHECK(child >= 0);
  if (child == 0)
    _exit(confinement(root));
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  fprintf(
      stderr,
      "pathconf: PASS retained cwd/root confinement and absolute symlink\n");

  int before = count();
  CHECK(before > 0 && before < 256);
  for (unsigned i = 0; i < 128; ++i)
    CHECK(pathconf(file, _PC_NAME_MAX) == 255);
  CHECK(count() == before);
  CHECK(unlink(alias) == 0 && unlink(dangling) == 0 && unlink(escape) == 0 &&
        unlink(file) == 0);
  CHECK(unlink(hidden_file) == 0 && rmdir(hidden) == 0 && rmdir(root) == 0);
  fprintf(stderr,
          "pathconf: PASS repeated queries reclaim all native references\n");
  return 0;
}
