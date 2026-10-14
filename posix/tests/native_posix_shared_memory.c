#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr,                                                          \
              "posix-shared-memory: FAIL line=%u errno=%d condition=%s\n",     \
              __LINE__, errno, #condition);                                    \
      return 1;                                                                \
    }                                                                          \
  } while (0)

int main(void) {
  const char *name = "/native-posix-shared-memory";
  int fd = shm_open(name, O_CREAT | O_EXCL | O_RDWR, 0600);
  CHECK(fd >= 0 && (fcntl(fd, F_GETFD, 0) & FD_CLOEXEC));
  struct stat original, observed;
  CHECK(fstat(fd, &original) == 0 && original.st_size == 0 &&
        original.st_nlink == 1);
  CHECK((original.st_mode & 0777) == 0600 && original.st_uid == geteuid() &&
        original.st_gid == getegid());
  CHECK(fcntl(fd, F_GETFL, 0) == O_RDWR);
  CHECK(shm_open(name, O_CREAT | O_EXCL | O_RDWR, 0600) == -1 &&
        errno == EEXIST);
  CHECK(shm_open(name, O_WRONLY, 0) == -1 && errno == EINVAL);
  CHECK(ftruncate(fd, 8192) == 0);
  volatile unsigned char *shared =
      mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  CHECK(shared != MAP_FAILED && shared[0] == 0 && shared[4096] == 0);
  shared[4096] = 42;
  int reader = shm_open(name, O_RDONLY, 0);
  CHECK(reader >= 0 && ftruncate(reader, 0) == -1 && errno == EBADF);
  CHECK(fstat(reader, &observed) == 0 && observed.st_ino == original.st_ino &&
        observed.st_size == 8192);
  CHECK(mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, reader, 0) ==
            MAP_FAILED &&
        errno == EACCES);
  volatile unsigned char *offset =
      mmap(NULL, 4096, PROT_READ, MAP_SHARED, reader, 4096);
  CHECK(offset != MAP_FAILED && offset[0] == 42);
  unsigned char byte = 17;
  CHECK(write(fd, &byte, 1) == 1 && shared[0] == 17);
  int alias = dup(fd);
  CHECK(alias >= 0 && !(fcntl(alias, F_GETFD, 0) & FD_CLOEXEC));
  CHECK(lseek(alias, 0, SEEK_CUR) == 1);
  CHECK(lseek(alias, 4096, SEEK_SET) == 4096 && read(fd, &byte, 1) == 1 &&
        byte == 42);
  CHECK(lseek(reader, 0, SEEK_CUR) == 0);
  CHECK(pwrite(alias, "x", 1, 1) == 1 && shared[1] == 'x');
  CHECK(lseek(fd, 0, SEEK_CUR) == 4097);
  CHECK(ftruncate(fd, 4097) == 0 && lseek(fd, 0, SEEK_CUR) == 4097);
  CHECK(ftruncate(fd, 8192) == 0 && shared[4097] == 0);
  CHECK(fcntl(alias, F_SETFL, O_APPEND | O_NONBLOCK) == 0);
  CHECK(fcntl(fd, F_GETFL, 0) == (O_RDWR | O_APPEND | O_NONBLOCK));
  CHECK(fcntl(reader, F_GETFL, 0) == O_RDONLY);
  CHECK(lseek(fd, 0, SEEK_SET) == 0 && write(alias, "a", 1) == 1);
  CHECK(lseek(fd, 0, SEEK_CUR) == 8193);
  CHECK(pread(fd, &byte, 1, 8192) == 1 && byte == 'a');
  CHECK(fcntl(fd, F_SETFL, 0) == 0 && fcntl(alias, F_GETFL, 0) == O_RDWR);
  CHECK(ftruncate(fd, 8192) == 0);
  CHECK(shm_unlink(name) == 0);
  CHECK(fstat(fd, &observed) == 0 && observed.st_nlink == 0 &&
        observed.st_ino == original.st_ino);
  CHECK(shm_open(name, O_RDONLY, 0) == -1 && errno == ENOENT);
  int fresh = shm_open(name, O_CREAT | O_EXCL | O_RDWR, 0600);
  CHECK(fresh >= 0 && ftruncate(fresh, 4096) == 0);
  CHECK(fstat(fresh, &observed) == 0 && observed.st_ino != original.st_ino &&
        observed.st_size == 4096 && observed.st_nlink == 1);
  volatile unsigned char *fresh_map =
      mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fresh, 0);
  CHECK(fresh_map != MAP_FAILED && fresh_map[0] == 0 && shared[0] == 17);
  CHECK(shm_unlink(name) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    if (lseek(alias, 2, SEEK_SET) != 2 || write(fd, "z", 1) != 1 ||
        fcntl(alias, F_SETFL, O_NONBLOCK) != 0)
      _exit(1);
    _exit(0);
  }
  int status = 0;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  CHECK(shared[2] == 'z' && lseek(fd, 0, SEEK_CUR) == 3);
  CHECK(fcntl(fd, F_GETFL, 0) == (O_RDWR | O_NONBLOCK));
  CHECK(close(fd) == 0 && close(alias) == 0 && close(reader) == 0 &&
        close(fresh) == 0);
  CHECK(shared[0] == 17 && offset[0] == 42 && fresh_map[0] == 0);
  CHECK(munmap((void *)shared, 8192) == 0 &&
        munmap((void *)offset, 4096) == 0 &&
        munmap((void *)fresh_map, 4096) == 0);
  fprintf(
      stderr,
      "posix-shared-memory: PASS newlib API, CLOEXEC, shared OFD, permissions, "
      "offset mapping, truncate, unlink lifetime, recreation, shared status "
      "flags, fstat identity and fork\n");
  return 0;
}
