#define PEEK_RECEIVE_TEST_ENTRY run_message_regressions
#include "native_peek_recvmsg.c"
#include <pty.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>

static int toggle_nonblocking(int fd, int alias, int persistent) {
  int descriptor_flags = fcntl(fd, F_GETFD);
  for (int enabled = -1; enabled <= 1; enabled++) {
    CHECK(ioctl(fd, FIONBIO, &enabled) == 0);
    int flags = fcntl(alias, F_GETFL);
    CHECK(flags >= 0 && !!(flags & O_NONBLOCK) == !!enabled);
    CHECK((flags & persistent) == persistent && fcntl(fd, F_GETFD) == descriptor_flags);
  }
  int enabled = 0;
  CHECK(ioctl(alias, FIONBIO, &enabled) == 0 && !(fcntl(fd, F_GETFL) & O_NONBLOCK));
  CHECK(ioctl(fd, FIONBIO, NULL) == -1 && errno == EFAULT);
  CHECK(ioctl(-1, FIONBIO) == -1 && errno == EBADF);
  return 0;
}

static int fionbio_sockets(void) {
  for (int kind = SOCK_STREAM; kind <= SOCK_DGRAM; kind++) {
    int pair[2]; char byte;
    CHECK(socketpair(AF_UNIX, kind | SOCK_CLOEXEC, 0, pair) == 0);
    int alias = dup(pair[1]);
    CHECK(alias >= 0 && toggle_nonblocking(pair[1], alias, 0) == 0);
    int enabled = 1;
    CHECK(ioctl(alias, FIONBIO, &enabled) == 0);
    CHECK(read(pair[1], &byte, 1) == -1 && errno == EAGAIN);
    enabled = 0;
    CHECK(ioctl(pair[1], FIONBIO, &enabled) == 0 && !(fcntl(alias, F_GETFL) & O_NONBLOCK));
    CHECK(write(pair[0], "s", 1) == 1 && read(alias, &byte, 1) == 1 && byte == 's');
    CHECK(close(alias) == 0 && close(pair[0]) == 0 && close(pair[1]) == 0);
  }
  puts("fionbio: PASS stream/datagram shared status and nonblocking reads");
  return 0;
}

static int fionbio_files(void) {
  int fd = open("/tmp/native-fionbio", O_CREAT | O_TRUNC | O_RDWR | O_APPEND | O_CLOEXEC, 0600);
  CHECK(fd >= 0 && unlink("/tmp/native-fionbio") == 0);
  int alias = dup(fd);
  CHECK(alias >= 0 && toggle_nonblocking(fd, alias, O_APPEND) == 0);
  CHECK(write(fd, "a", 1) == 1 && lseek(alias, 0, SEEK_SET) == 0 && write(alias, "b", 1) == 1);
  char bytes[2];
  CHECK(pread(fd, bytes, 2, 0) == 2 && !memcmp(bytes, "ab", 2));
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    int enabled = 1;
    _exit(ioctl(alias, FIONBIO, &enabled) == 0 ? 0 : 1);
  }
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  CHECK((fcntl(fd, F_GETFL) & (O_APPEND | O_NONBLOCK)) == (O_APPEND | O_NONBLOCK));
  CHECK(close(fd) == 0 && close(alias) == 0);
  fd = open("/tmp", O_RDONLY | O_DIRECTORY);
  CHECK(fd >= 0 && toggle_nonblocking(fd, fd, 0) == 0 && close(fd) == 0);
  fd = open("/dev/null", O_RDWR | O_APPEND);
  CHECK(fd >= 0 && toggle_nonblocking(fd, fd, O_APPEND) == 0 && close(fd) == 0);
  puts("fionbio: PASS unlinked file, append preservation, dup/fork sharing, directory and null device");
  return 0;
}

static int fionbio_other_descriptions(void) {
  int pair[2], enabled = 1; char byte;
  CHECK(pipe(pair) == 0);
  int alias = dup(pair[0]);
  CHECK(alias >= 0 && toggle_nonblocking(pair[0], alias, 0) == 0);
  CHECK(ioctl(alias, FIONBIO, &enabled) == 0 && read(pair[0], &byte, 1) == -1 && errno == EAGAIN);
  CHECK(close(alias) == 0 && close(pair[0]) == 0 && close(pair[1]) == 0);
  CHECK(openpty(&pair[0], &pair[1], NULL, NULL, NULL) == 0);
  CHECK(toggle_nonblocking(pair[0], pair[0], 0) == 0);
  CHECK(toggle_nonblocking(pair[1], pair[1], 0) == 0);
  CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
  shm_unlink("/native-fionbio");
  int fd = shm_open("/native-fionbio", O_CREAT | O_EXCL | O_RDWR, 0600);
  CHECK(fd >= 0 && shm_unlink("/native-fionbio") == 0);
  CHECK(fcntl(fd, F_SETFL, O_APPEND) == 0);
  alias = dup(fd);
  CHECK(alias >= 0 && toggle_nonblocking(fd, alias, O_APPEND) == 0);
  CHECK(close(alias) == 0 && close(fd) == 0);
  puts("fionbio: PASS pipe, PTY and shared-memory description flags");
  return 0;
}

int main(void) {
  CHECK(run_message_regressions() == 0);
  CHECK(fionbio_sockets() == 0 && fionbio_files() == 0 && fionbio_other_descriptions() == 0);
  puts("fionbio: PASS native atomic nonblocking updates without replacing unrelated OFD flags");
  return 0;
}
