/* Actual newlib -> POSIX -> filesystem byte pathname integration. */
#define main directory_baseline_main
#include "native_directory_io.c"
#undef main
#include <stdlib.h>

int main(void) {
  char original[4097], directory[128], output[1024], expected[256];
  const char file[] = "file-\xff", alias[] = "alias-\xfe";
  const char renamed[] = "renamed-\xfd", sym[] = "symlink-\xfc";
  CHECK(getcwd(original, sizeof(original)) == original);
  snprintf(directory, sizeof(directory), "/tmp/byte-path-%d-\xfb",
           (int)getpid());
  CHECK(mkdir(directory, 0700) == 0 && chdir(directory) == 0);
  CHECK(getcwd(output, sizeof(output)) == output &&
        strcmp(output, directory) == 0);
  CHECK(realpath(".", output) == output && strcmp(output, directory) == 0);
  int64_t baseline = native_count();
  for (unsigned round = 0; round < 16; ++round) {
    int fd = open(file, O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(fd >= 0 && write(fd, "abc", 3) == 3 && close(fd) == 0);
    CHECK(access(file, R_OK | W_OK) == 0);
    CHECK(chmod(file, 0640) == 0);
    CHECK(chown(file, (uid_t)-1, (gid_t)-1) == 0);
    CHECK(link(file, alias) == 0 && symlink(alias, sym) == 0);
    struct stat status;
    CHECK(stat(sym, &status) == 0 && status.st_size == 3 &&
          status.st_nlink == 2);
    memset(output, 0x5a, sizeof(output));
    CHECK(readlink(sym, output, sizeof(output)) == (ssize_t)strlen(alias));
    CHECK(memcmp(output, alias, strlen(alias)) == 0 &&
          output[strlen(alias)] == 0x5a);
    snprintf(expected, sizeof(expected), "%s/%s", directory, alias);
    CHECK(realpath(sym, output) == output && strcmp(output, expected) == 0);
    char *allocated = realpath(sym, NULL);
    CHECK(allocated && strcmp(allocated, expected) == 0);
    free(allocated);
    CHECK(truncate(file, 1) == 0 && stat(alias, &status) == 0 &&
          status.st_size == 1);
    CHECK(rename(alias, renamed) == 0);
    errno = 0;
    CHECK(stat(sym, &status) == -1 && errno == ENOENT);
    CHECK(unlink(sym) == 0 && unlink(renamed) == 0 && unlink(file) == 0);
    CHECK(mkdir("child-\xfa", 0700) == 0);
    CHECK(rename("child-\xfa", "moved-\xf9") == 0 && rmdir("moved-\xf9") == 0);
    CHECK(native_count() == baseline);
  }
  CHECK(chdir(original) == 0 && rmdir(directory) == 0);
  CHECK(native_count() == baseline);
  puts("byte-paths: PASS 16 rounds raw cwd, open, access, chmod/chown, stat, "
       "link/symlink, readlink, realpath, truncate, rename, unlink and stable "
       "Handle counts");
  return 0;
}
