/* Real libc -> POSIX -> filesystem FIFO creation; data-open support is
 * separate. */
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
      fprintf(stderr, "mkfifo: FAIL line=%u errno=%d: %s\n", __LINE__, errno,  \
              #x);                                                             \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static int permissions(const char *root) {
  CHECK(setgid(20) == 0 && setuid(501) == 0);
  char path[160];
  snprintf(path, sizeof(path), "%s/forbidden", root);
  CHECK(mkfifo(path, 0666) == -1 && errno == EACCES);
  snprintf(path, sizeof(path), "%s/shared/owned", root);
  CHECK(mkfifo(path, 0666) == 0);
  struct stat st;
  CHECK(stat(path, &st) == 0 && S_ISFIFO(st.st_mode));
  CHECK(st.st_uid == 501 && st.st_gid == 777 && (st.st_mode & 0777) == 0640);
  return 0;
}

static int confinement(const char *root) {
  CHECK(chroot(root) == 0 && chdir("/") == 0);
  CHECK(mkfifo("/../confined", 0600) == 0);
  struct stat st;
  CHECK(stat("/confined", &st) == 0 && S_ISFIFO(st.st_mode));
  CHECK(mkfifo("/tmp/escape", 0600) == -1 && errno == ENOENT);
  return 0;
}

int main(void) {
  alarm(60);
  char root[96], path[160], moved[128], shared[128];
  snprintf(root, sizeof(root), "/tmp/fifo-creation-%ld", (long)getpid());
  snprintf(moved, sizeof(moved), "%s-moved", root);
  snprintf(shared, sizeof(shared), "%s/shared", root);
  CHECK(mkdir(root, 0755) == 0);
  mode_t oldmask = umask(0027);
  snprintf(path, sizeof(path), "%s/first", root);
  errno = 73;
  CHECK(mkfifo(path, 0666) == 0 && errno == 73);
  struct stat first, st;
  CHECK(stat(path, &first) == 0 && S_ISFIFO(first.st_mode));
  CHECK((first.st_mode & 0777) == 0640 && first.st_nlink == 1 &&
        first.st_size == 0);
  CHECK(mkfifo(path, 0777) == -1 && errno == EEXIST);
  CHECK(stat(path, &st) == 0 && st.st_ino == first.st_ino &&
        (st.st_mode & 0777) == 0640);
  puts("mkfifo: PASS creation-mode-identity");

  int directory = open(root, O_RDONLY | O_DIRECTORY);
  CHECK(directory >= 0 && rename(root, moved) == 0);
  CHECK(mkfifoat(directory, "relative\xff", 0600) == 0);
  CHECK(fstatat(directory, "relative\xff", &st, 0) == 0 &&
        S_ISFIFO(st.st_mode));
  CHECK(rename(moved, root) == 0);
  snprintf(path, sizeof(path), "%s/absolute", root);
  CHECK(mkfifoat(-999, path, 0600) == 0);
  CHECK(mkfifoat(-999, "relative", 0600) == -1 && errno == EBADF);
  puts("mkfifo: PASS directory-handle-and-absolute-path");

  snprintf(path, sizeof(path), "%s/dangling", root);
  CHECK(symlink("absent", path) == 0);
  CHECK(mkfifo(path, 0600) == -1 && errno == EEXIST);
  CHECK(mkfifoat(directory, "absent/", 0600) == -1 && errno == ENOENT);
  CHECK(mkfifoat(directory, (const char *)(uintptr_t)1, 0600) == -1 &&
        errno == EFAULT);
  CHECK(mkfifoat(directory, NULL, 0600) == -1 && errno == EFAULT);
  char oversized[4098];
  memset(oversized, 'x', sizeof(oversized) - 1);
  oversized[sizeof(oversized) - 1] = 0;
  CHECK(mkfifoat(directory, oversized, 0600) == -1 && errno == ENAMETOOLONG);
  CHECK(fstatat(directory, "absent", &st, 0) == -1 && errno == ENOENT);
  puts("mkfifo: PASS failures-without-creation");

  CHECK(mkdir(shared, 0777) == 0 && chown(shared, 0, 777) == 0 &&
        chmod(shared, 02777) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0)
    _exit(permissions(root));
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  puts("mkfifo: PASS authenticated-permissions-and-parent-group");
  child = fork();
  CHECK(child >= 0);
  if (child == 0)
    _exit(confinement(root));
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  puts("mkfifo: PASS process-root-confinement");

  /* FIFO data endpoints are not connected yet: explicitly reject disk open. */
  CHECK(openat(directory, "first", O_RDWR | O_TRUNC) == -1 && errno == ENOTSUP);
  CHECK(fstatat(directory, "first", &st, 0) == 0 && S_ISFIFO(st.st_mode) &&
        st.st_size == 0);
  CHECK(unlinkat(directory, "first", 0) == 0 && close(directory) == 0);
  umask(oldmask);
  puts("mkfifo: PASS disk-io-rejection-and-unlink");
  return 0;
}
