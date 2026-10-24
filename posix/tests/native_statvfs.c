#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <unistd.h>
_Static_assert(sizeof(struct statvfs) == 80, "newlib statvfs size");
_Static_assert(offsetof(struct statvfs, f_files) == 40, "inode counter layout");
_Static_assert(offsetof(struct statvfs, f_fsid) == 56, "zero padding layout");
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "statvfs: FAIL line=%u errno=%d: %s\n", __LINE__, errno, \
              #x);                                                             \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static int same_volume(const struct statvfs *a, const struct statvfs *b) {
  return a->f_fsid == b->f_fsid && a->f_blocks == b->f_blocks &&
         a->f_frsize == b->f_frsize;
}
extern int posix_openpt(int);
extern int grantpt(int);
extern int unlockpt(int);
extern int ptsname_r(int, char *, size_t);
static int device_volume(void) {
  struct statvfs device, observed;
  CHECK(statvfs("/dev", &device) == 0);
  CHECK(device.f_frsize == 1 && device.f_blocks == 0 && device.f_bfree == 0 &&
        device.f_bavail == 0);
  CHECK(device.f_files == UINT32_MAX && device.f_ffree < device.f_files &&
        device.f_favail == device.f_ffree);
  CHECK(statvfs("/dev/null", &observed) == 0 &&
        same_volume(&device, &observed));
  for (int writeonly = 0; writeonly != 2; writeonly++) {
    int fd = open("/dev/null", writeonly ? O_WRONLY : O_RDONLY);
    CHECK(fd >= 0);
    CHECK(fstatvfs(fd, &observed) == 0 && same_volume(&device, &observed));
    CHECK(close(fd) == 0);
  }
  int directory = open("/dev", O_RDONLY | O_DIRECTORY);
  CHECK(directory >= 0);
  CHECK(fstatvfs(directory, &observed) == 0 && same_volume(&device, &observed));
  CHECK(close(directory) == 0);
  int master = posix_openpt(O_RDWR | O_NOCTTY);
  CHECK(master >= 0);
  char name[128];
  CHECK(grantpt(master) == 0 && unlockpt(master) == 0 &&
        ptsname_r(master, name, sizeof(name)) == 0);
  int slave = open(name, O_RDWR | O_NOCTTY);
  CHECK(slave >= 0);
  CHECK(statvfs(name, &observed) == 0 && same_volume(&device, &observed));
  CHECK(observed.f_ffree < device.f_ffree);
  CHECK(fstatvfs(slave, &observed) == 0 && same_volume(&device, &observed));
  CHECK(close(master) == 0);
  int removed = 0;
  for (unsigned attempt = 0; attempt < 1000; attempt++) {
    if (statvfs(name, &observed) == -1) {
      CHECK(errno == ENOENT);
      removed = 1;
      break;
    }
    usleep(1000);
  }
  CHECK(removed && fstatvfs(slave, &observed) == 0 &&
        same_volume(&device, &observed));
  CHECK(observed.f_ffree < device.f_ffree && close(slave) == 0);
  puts("statvfs: PASS devfs-null-directory-and-unpublished-terminal");
  fflush(stdout);
  return 0;
}
int main(void) {
  alarm(45);
  struct statvfs data, system, observed;
  errno = 71;
  CHECK(statvfs("/tmp", &data) == 0 && errno == 71);
  CHECK(data.f_frsize > 0 && data.f_bsize == data.f_frsize &&
        data.f_blocks > data.f_bfree && data.f_bavail == data.f_bfree);
  CHECK(data.f_files > data.f_ffree && data.f_favail == data.f_ffree &&
        data.f_namemax == 255 && !(data.f_flag & ST_RDONLY));
  CHECK(statvfs("/system", &system) == 0 && (system.f_flag & ST_RDONLY) &&
        system.f_fsid != data.f_fsid);
  int systemfd = open("/system", O_RDONLY | O_DIRECTORY);
  CHECK(systemfd >= 0 && fstatvfs(systemfd, &observed) == 0 &&
        same_volume(&system, &observed));
  CHECK(close(systemfd) == 0);
  CHECK(device_volume() == 0);
  puts("statvfs: PASS live-data-system-readonly-volumes");
  fflush(stdout);
  char root[128], path[160], moved[160], fifo[160], blocked[160];
  snprintf(root, sizeof(root), "/tmp/statvfs-%ld", (long)getpid());
  CHECK(mkdir(root, 0755) == 0);
  snprintf(path, sizeof(path), "%s/file\xff", root);
  snprintf(moved, sizeof(moved), "%s/moved", root);
  snprintf(fifo, sizeof(fifo), "%s/fifo", root);
  snprintf(blocked, sizeof(blocked), "%s/blocked", root);
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  CHECK(fd >= 0);
  CHECK(write(fd, "abc", 3) == 3);
  CHECK(fstatvfs(fd, &observed) == 0 && same_volume(&data, &observed));
  CHECK(lseek(fd, 0, SEEK_CUR) == 3);
  int duplicate = dup(fd);
  CHECK(duplicate >= 0 && rename(path, moved) == 0 && unlink(moved) == 0);
  CHECK(fstatvfs(duplicate, &observed) == 0 && same_volume(&data, &observed));
  CHECK(close(duplicate) == 0 && close(fd) == 0);
  puts("statvfs: PASS writeonly-dup-unlinked-retained-fd");
  fflush(stdout);
  CHECK(mkfifo(fifo, 0600) == 0);
  fd = open(fifo, O_RDONLY | O_NONBLOCK);
  CHECK(fd >= 0);
  CHECK(unlink(fifo) == 0 && fstatvfs(fd, &observed) == 0 &&
        same_volume(&data, &observed));
  CHECK(close(fd) == 0);
  puts("statvfs: PASS fifo-filesystem-metadata-delegation");
  fflush(stdout);
  fd = open(path, O_RDONLY | O_CREAT | O_EXCL, 0000);
  CHECK(fd >= 0 && mkdir(blocked, 0000) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(setgid(20) == 0 && setuid(501) == 0);
    CHECK(statvfs(path, &observed) == 0 && same_volume(&data, &observed));
    char denied[180];
    snprintf(denied, sizeof(denied), "%s/child", blocked);
    CHECK(statvfs(denied, &observed) == -1 && errno == EACCES);
    _exit(0);
  }
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(chroot(root) == 0 && chdir("/") == 0);
    CHECK(statvfs("/", &observed) == 0 && same_volume(&data, &observed));
    CHECK(statvfs("/system", &observed) == -1 && errno == ENOENT);
    _exit(0);
  }
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  puts("statvfs: PASS search-permissions-and-root-confinement");
  fflush(stdout);
  CHECK(fstatvfs(fd, (struct statvfs *)(uintptr_t)1) == -1 && errno == EFAULT);
  CHECK(fstatvfs(-1, &observed) == -1 && errno == EBADF);
  CHECK(statvfs((const char *)(uintptr_t)1, &observed) == -1 &&
        errno == EFAULT);
  CHECK(statvfs("/missing", &observed) == -1 && errno == ENOENT);
  CHECK(fstatvfs(fd, &observed) == 0);
  int pipefd[2];
  CHECK(pipe(pipefd) == 0);
  CHECK(fstatvfs(pipefd[0], &observed) == -1 && errno == ENOTSUP);
  CHECK(close(pipefd[0]) == 0 && close(pipefd[1]) == 0);
  CHECK(close(fd) == 0 && unlink(path) == 0 && rmdir(blocked) == 0 &&
        rmdir(root) == 0);
  puts("statvfs: PASS errors-fault-safe-output-and-cleanup");
  fflush(stdout);
  return 0;
}
