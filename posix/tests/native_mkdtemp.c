#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <reent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "native-mkdtemp: FAIL line=%d errno=%d: %s\n", __LINE__, \
              errno, #x);                                                      \
      return 1;                                                                \
    }                                                                          \
  } while (0)
int main(void) {
  char first[] = "/tmp/native-mkdtemp-XXXXXX";
  char second[] = "/tmp/native-mkdtemp-XXXXXX";
  struct stat status;
  CHECK(mkdtemp(first) == first);
  CHECK(stat(first, &status) == 0 && S_ISDIR(status.st_mode) &&
        (status.st_mode & 0777) == 0700);
  char sentinel[128];
  CHECK(snprintf(sentinel, sizeof(sentinel), "%s/sentinel", first) > 0);
  int fd = open(sentinel, O_CREAT | O_EXCL | O_RDWR, 0600);
  CHECK(fd >= 0 && write(fd, "x", 1) == 1 && close(fd) == 0);
  CHECK(chmod(first, 0755) == 0);
  CHECK(mkdtemp(second) == second && strcmp(first, second));
  CHECK(stat(first, &status) == 0 && (status.st_mode & 0777) == 0755);
  CHECK(stat(second, &status) == 0 && (status.st_mode & 0777) == 0700);

  char link_name[] = "/tmp/native-mkdtemp-link-XXXXXX";
  char after_link[] = "/tmp/native-mkdtemp-link-XXXXXX";
  CHECK(mkdtemp(link_name) == link_name && rmdir(link_name) == 0);
  CHECK(symlink(first, link_name) == 0);
  CHECK(mkdtemp(after_link) == after_link && strcmp(link_name, after_link));
  char target[128];
  ssize_t target_length = readlink(link_name, target, sizeof(target));
  CHECK(target_length == (ssize_t)strlen(first) &&
        !memcmp(target, first, target_length));
  CHECK(stat(first, &status) == 0 && (status.st_mode & 0777) == 0755);
  fd = open(sentinel, O_RDONLY);
  char byte = 0;
  CHECK(fd >= 0 && read(fd, &byte, 1) == 1 && byte == 'x' && close(fd) == 0);

  char invalid[] = "/tmp/native-mkdtemp-XXXXX";
  CHECK(mkdtemp(invalid) == NULL && errno == EINVAL);
  struct _reent isolated = {0};
  char reentrant[] = "/tmp/native-mkdtemp-reentrant-XXXXXX";
  CHECK(_mkdtemp_r(&isolated, reentrant) == reentrant);
  char bad_reentrant[] = "/tmp/native-mkdtemp-XXXXX";
  CHECK(_mkdtemp_r(&isolated, bad_reentrant) == NULL &&
        isolated._errno == EINVAL);
  char absent[128];
  CHECK(snprintf(absent, sizeof(absent), "%s/absent/child-XXXXXX", first) > 0);
  CHECK(mkdtemp(absent) == NULL && errno == ENOENT);

  /* All these exports share newlib's object file. Exercise them together
   * so replacing just one symbol cannot conceal duplicate-definition bugs. */
  char file[] = "/tmp/native-mkstemp-XXXXXX";
  CHECK((fd = mkstemp(file)) >= 0 && close(fd) == 0 && unlink(file) == 0);
  char cloexec[] = "/tmp/native-mkostemp-XXXXXX";
  CHECK((fd = mkostemp(cloexec, O_CLOEXEC)) >= 0);
  CHECK((fcntl(fd, F_GETFD) & FD_CLOEXEC) && close(fd) == 0 &&
        unlink(cloexec) == 0);
  char suffix[] = "/tmp/native-mkstemps-XXXXXX.txt";
  CHECK((fd = mkstemps(suffix, 4)) >= 0);
  CHECK(!strcmp(suffix + strlen(suffix) - 4, ".txt") && close(fd) == 0 &&
        unlink(suffix) == 0);
  for (unsigned length = 59; length <= 61; ++length) {
    char boundary[128], destination[62], readback[62];
    CHECK(snprintf(boundary, sizeof(boundary), "%s/link-%u", first, length) >
          0);
    memset(destination, 'x', length);
    destination[length] = 0;
    CHECK(symlink(destination, boundary) == 0);
    CHECK(readlink(boundary, readback, sizeof(readback)) == (ssize_t)length);
    CHECK(!memcmp(destination, readback, length) && unlink(boundary) == 0);
  }
  CHECK(unlink(sentinel) == 0 && unlink(link_name) == 0);
  CHECK(rmdir(first) == 0 && rmdir(second) == 0 && rmdir(after_link) == 0 &&
        rmdir(reentrant) == 0);
  puts("native-mkdtemp: PASS mode0700, collisions, symlink preservation, "
       "errors, reentrant API and file-template coexistence");
  return 0;
}
