#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "symlink-trailing: FAIL line=%u errno=%d: %s\n",         \
              __LINE__, errno, #x);                                            \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static int64_t native_count(void) {
  uint64_t number = 680;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(0ULL), "S"(0ULL), "d"(0ULL)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
int main(void) {
  alarm(60);
  char root[96], file[128], dir[128], bad[128], good[128], chain[128],
      dangling[128];
  char missing[128], child[160], subdir[160], renamed[128], bad_renamed[128];
  snprintf(root, sizeof(root), "/tmp/symlink-trailing-%d", (int)getpid());
  snprintf(file, sizeof(file), "%s/file", root);
  snprintf(dir, sizeof(dir), "%s/dir", root);
  snprintf(bad, sizeof(bad), "%s/bad", root);
  snprintf(good, sizeof(good), "%s/good", root);
  snprintf(chain, sizeof(chain), "%s/chain", root);
  snprintf(dangling, sizeof(dangling), "%s/dangling", root);
  snprintf(missing, sizeof(missing), "%s/missing", root);
  snprintf(child, sizeof(child), "%s/child", good);
  snprintf(subdir, sizeof(subdir), "%s/subdir", good);
  snprintf(renamed, sizeof(renamed), "%s/renamed", root);
  snprintf(bad_renamed, sizeof(bad_renamed), "%s/bad-renamed", root);
  CHECK(mkdir(root, 0700) == 0);
  int warm = open(root, O_RDONLY | O_DIRECTORY);
  CHECK(warm >= 0 && close(warm) == 0);
  int64_t baseline = native_count();
  int fd = open(file, O_CREAT | O_EXCL | O_RDWR, 0600);
  CHECK(fd >= 0 && write(fd, "preserved", 9) == 9);
  CHECK(mkdir(dir, 0700) == 0 && symlink("file/", bad) == 0 &&
        symlink("bad", chain) == 0);
  struct stat status;
  for (int i = 0; i < 2; i++) {
    const char *path = i == 0 ? bad : chain;
    CHECK(stat(path, &status) == -1 && errno == ENOTDIR);
    CHECK(open(path, O_RDONLY) == -1 && errno == ENOTDIR);
    CHECK(open(path, O_WRONLY | O_TRUNC) == -1 && errno == ENOTDIR);
    CHECK(truncate(path, 0) == -1 && errno == ENOTDIR);
  }
  char bytes[32];
  CHECK(pread(fd, bytes, 9, 0) == 9 && !memcmp(bytes, "preserved", 9));
  CHECK(lstat(bad, &status) == 0 && S_ISLNK(status.st_mode));
  CHECK(readlink(bad, bytes, sizeof(bytes)) == 5 && !memcmp(bytes, "file/", 5));
  fprintf(stderr, "symlink-trailing: PASS regular-file targets and chains "
                  "reject access before truncation\n");

  CHECK(symlink("dir/", good) == 0 && stat(good, &status) == 0 &&
        S_ISDIR(status.st_mode));
  int directory = open(good, O_RDONLY | O_DIRECTORY);
  CHECK(directory >= 0 && close(directory) == 0);
  int leaf = open(child, O_CREAT | O_EXCL | O_RDWR, 0600);
  CHECK(leaf >= 0 && write(leaf, "leaf", 4) == 4 && close(leaf) == 0);
  CHECK(stat(child, &status) == 0 && S_ISREG(status.st_mode));
  CHECK(mkdir(subdir, 0700) == 0);
  fprintf(stderr, "symlink-trailing: PASS directory target with regular-file "
                  "and directory suffixes\n");

  CHECK(symlink("missing/", dangling) == 0);
  CHECK(open(dangling, O_CREAT | O_RDWR, 0600) == -1 && errno == ENOENT);
  CHECK(lstat(missing, &status) == -1 && errno == ENOENT);
  CHECK(unlink(dangling) == 0);
  fprintf(stderr, "symlink-trailing: PASS missing directory is not created as "
                  "a regular file\n");

  CHECK(rename(good, renamed) == 0 && lstat(renamed, &status) == 0 &&
        S_ISLNK(status.st_mode));
  CHECK(unlink(renamed) == 0 && stat(dir, &status) == 0 &&
        S_ISDIR(status.st_mode));
  CHECK(rename(bad, bad_renamed) == 0 && unlink(bad_renamed) == 0);
  CHECK(stat(file, &status) == 0 && status.st_size == 9);
  CHECK(unlink(chain) == 0 && close(fd) == 0);
  snprintf(child, sizeof(child), "%s/child", dir);
  snprintf(subdir, sizeof(subdir), "%s/subdir", dir);
  CHECK(unlink(child) == 0 && rmdir(subdir) == 0 && rmdir(dir) == 0);
  CHECK(unlink(file) == 0 && rmdir(root) == 0 && native_count() == baseline);
  fprintf(stderr, "symlink-trailing: PASS rename/unlink keep literal links and "
                  "reclaim Handles\n");
  return 0;
}
