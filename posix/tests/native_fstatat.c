#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "native-fstatat: FAIL line=%d errno=%d: %s\n", __LINE__, \
              errno, #x);                                                      \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static int same(const struct stat *a, const struct stat *b) {
  return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
         a->st_size == b->st_size && a->st_mode == b->st_mode;
}
int main(void) {
  char first[] = "/tmp/native-fstatat-first-XXXXXX",
       second[] = "/tmp/native-fstatat-second-XXXXXX";
  CHECK(mkdtemp(first) && mkdtemp(second));
  int directory = open(first, O_RDONLY | O_DIRECTORY);
  int other = open(second, O_RDONLY | O_DIRECTORY);
  CHECK(directory >= 0 && other >= 0);
  int file = openat(directory, "entry", O_CREAT | O_EXCL | O_RDWR, 0600);
  int replacement = openat(other, "entry", O_CREAT | O_EXCL | O_RDWR, 0600);
  CHECK(file >= 0 && replacement >= 0);
  CHECK(write(file, "first", 5) == 5 &&
        write(replacement, "elsewhere", 9) == 9);
  struct stat expected, alternative, result;
  CHECK(fstat(file, &expected) == 0 && fstat(replacement, &alternative) == 0);
  CHECK(fstatat(directory, "entry", &result, 0) == 0 &&
        same(&result, &expected));
  char cwd[1024];
  CHECK(getcwd(cwd, sizeof(cwd)) && chdir(second) == 0);
  CHECK(fstatat(directory, "entry", &result, 0) == 0 &&
        same(&result, &expected));
  CHECK(fstatat(AT_FDCWD, "entry", &result, 0) == 0 &&
        same(&result, &alternative));
  CHECK(fstatat(-100, "entry", &result, 0) == 0 && same(&result, &alternative));
  CHECK(chdir(cwd) == 0);
  CHECK(symlinkat("entry", directory, "link") == 0 &&
        symlinkat("missing", directory, "broken") == 0);
  CHECK(fstatat(directory, "link", &result, 0) == 0 &&
        same(&result, &expected));
  struct stat link_status;
  CHECK(fstatat(directory, "link", &link_status, AT_SYMLINK_NOFOLLOW) == 0);
  CHECK(S_ISLNK(link_status.st_mode) && link_status.st_size == 5);
  char absolute[128], moved[128];
  CHECK(snprintf(absolute, sizeof(absolute), "%s/link", first) > 0);
  CHECK(lstat(absolute, &result) == 0 && same(&result, &link_status));
  CHECK(stat(absolute, &result) == 0 && same(&result, &expected));
  CHECK(fstatat(-123, absolute, &result, 0) == 0 && same(&result, &expected));
  CHECK(fstatat(directory, "broken", &result, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISLNK(result.st_mode));

  struct stat untouched;
  memset(&untouched, 0xa5, sizeof(untouched));
  memcpy(&result, &untouched, sizeof(result));
  CHECK(fstatat(directory, "broken", &result, 0) == -1 && errno == ENOENT);
  CHECK(!memcmp(&result, &untouched, sizeof(result)));
  CHECK(fstatat(-123, "entry", &result, 0) == -1 && errno == EBADF);
  CHECK(fstatat(file, "entry", &result, 0) == -1 && errno == ENOTDIR);
  CHECK(fstatat(directory, "", &result, 0) == -1 && errno == ENOENT);
  CHECK(fstatat(directory, "entry", &result, -1) == -1 && errno == EINVAL);
  char too_long[8193];
  memset(too_long, 'x', sizeof(too_long) - 1);
  too_long[sizeof(too_long) - 1] = 0;
  CHECK(fstatat(directory, too_long, &result, 0) == -1 &&
        errno == ENAMETOOLONG);
  int (*volatile call)(int, const char *, struct stat *, int) = fstatat;
  CHECK(call(directory, NULL, &result, 0) == -1 && errno == EFAULT);
  CHECK(call(directory, "entry", NULL, 0) == -1 && errno == EFAULT);
  CHECK(!memcmp(&result, &untouched, sizeof(result)));
  CHECK(stat("", &result) == -1 && errno == ENOENT);
  CHECK(lstat("", &result) == -1 && errno == ENOENT);

  CHECK(snprintf(moved, sizeof(moved), "%s-moved", first) > 0);
  CHECK(rename(first, moved) == 0);
  CHECK(fstatat(directory, "entry", &result, 0) == 0 &&
        same(&result, &expected));
  CHECK(rename(moved, first) == 0);
  CHECK(unlinkat(directory, "link", 0) == 0 &&
        unlinkat(directory, "broken", 0) == 0);
  CHECK(unlinkat(directory, "entry", 0) == 0 &&
        unlinkat(other, "entry", 0) == 0);
  CHECK(fstat(file, &result) == 0 && result.st_size == 5);
  CHECK(close(file) == 0 && close(replacement) == 0 && close(directory) == 0 &&
        close(other) == 0);
  CHECK(rmdir(first) == 0 && rmdir(second) == 0);
  puts("native-fstatat: PASS relative authority, nofollow, cwd, rename, errors "
       "and unchanged failed output");
  return 0;
}
