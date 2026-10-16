/* Exercise real libc metadata paths, including nonlocal escape on copyout. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned kind, fault;
static int descriptor, auxiliary;
static char path[96], shared_name[96];
static volatile sig_atomic_t faulted;
static sigjmp_buf destination;
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(                                                                 \
          stderr,                                                              \
          "descriptor-metadata: FAIL kind=%u fault=%u line=%u errno=%d: %s\n", \
          kind, fault, __LINE__, errno, #x);                                   \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static int64_t native_count(void) {
  uint64_t number = 680;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"((uint64_t)0), "S"((uint64_t)0), "d"((uint64_t)0)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
static int create(void) {
  auxiliary = -1;
  switch (kind) {
  case 0:
    return open(path, O_CREAT | O_RDWR, 0600);
  case 1:
    return open("/tmp", O_RDONLY);
  case 2:
  case 3: {
    int pair[2];
    if (pipe(pair))
      return -1;
    auxiliary = pair[kind == 2 ? 1 : 0];
    return pair[kind == 2 ? 0 : 1];
  }
  case 4:
    return socket(AF_UNIX, SOCK_STREAM, 0);
  case 5:
    return socket(AF_UNIX, SOCK_DGRAM, 0);
  case 6: {
    int fd = shm_open(shared_name, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd >= 0 && shm_unlink(shared_name)) {
      close(fd);
      return -1;
    }
    return fd;
  }
  case 7: {
    int slave;
    if (openpty(&auxiliary, &slave, NULL, NULL, NULL))
      return -1;
    return slave;
  }
  }
  return -1;
}
static void failed_copy(int signal) {
  if (signal != SIGSEGV)
    _exit(91);
  if (close(descriptor))
    _exit(92);
  faulted = 1;
  siglongjmp(destination, 37);
}
static int valid_kind(const struct stat *status) {
  switch (kind) {
  case 0:
  case 6:
    return S_ISREG(status->st_mode);
  case 1:
    return S_ISDIR(status->st_mode);
  case 2:
  case 3:
    return S_ISFIFO(status->st_mode);
  case 4:
  case 5:
    return S_ISSOCK(status->st_mode);
  case 7:
    return S_ISCHR(status->st_mode);
  }
  return 0;
}
int main(void) {
  snprintf(path, sizeof(path), "/tmp/descriptor-metadata-%d", (int)getpid());
  snprintf(shared_name, sizeof(shared_name), "/descriptor-metadata-%d",
           (int)getpid());
  CHECK(unlink(path) == 0 || errno == ENOENT);
  CHECK(shm_unlink(shared_name) == 0 || errno == ENOENT);
  /* Resolve all lazy endpoints before measuring reference recovery. */
  for (kind = 0; kind < 8; ++kind) {
    descriptor = create();
    CHECK(descriptor >= 0);
    struct stat status;
    CHECK(fstat(descriptor, &status) == 0 && valid_kind(&status));
    if (kind == 0) {
      CHECK(ftruncate(descriptor, 0) == 0);
      CHECK(write(descriptor, "abc", 3) == 3);
      int alias = dup(descriptor);
      CHECK(alias >= 0 && lseek(alias, 1, SEEK_SET) == 1);
      CHECK(lseek(descriptor, 0, SEEK_CUR) == 1);
      char byte;
      CHECK(read(descriptor, &byte, 1) == 1 && byte == 'b');
      CHECK(lseek(alias, 0, SEEK_CUR) == 2 && close(alias) == 0);
      CHECK(fchmod(descriptor, 0640) == 0);
      CHECK(fchown(descriptor, (uid_t)-1, (gid_t)-1) == 0);
      CHECK(fstat(descriptor, &status) == 0 && (status.st_mode & 0777) == 0640);
      CHECK(status.st_size == 3);
      CHECK(fsync(descriptor) == 0 && fdatasync(descriptor) == 0);
    }
    CHECK(close(descriptor) == 0);
    if (auxiliary >= 0)
      CHECK(close(auxiliary) == 0);
  }
  struct sigaction action = {0};
  action.sa_handler = failed_copy;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  for (kind = 0; kind < 8; ++kind) {
    for (fault = 0; fault < 2; ++fault) {
      int64_t baseline = native_count();
      CHECK(baseline > 0);
      descriptor = create();
      CHECK(descriptor >= 0);
      void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      CHECK(page != MAP_FAILED);
      if (fault)
        CHECK(mprotect(page, 4096, PROT_READ) == 0);
      faulted = 0;
      int jumped = sigsetjmp(destination, 1);
      if (!jumped) {
        CHECK(fstat(descriptor, page) == 0 && !fault && valid_kind(page));
        CHECK(close(descriptor) == 0);
      } else {
        CHECK(jumped == 37 && fault && faulted);
        CHECK(fcntl(descriptor, F_GETFD) == -1 && errno == EBADF);
      }
      CHECK(faulted == (sig_atomic_t)fault);
      CHECK(munmap(page, 4096) == 0);
      if (auxiliary >= 0)
        CHECK(close(auxiliary) == 0);
      CHECK(native_count() == baseline);
      fprintf(stderr, "descriptor-metadata: kind=%u fault=%u PASS\n", kind,
              fault);
    }
  }
  CHECK(unlink(path) == 0);
  puts("descriptor-metadata: PASS 16 copyout cases; shared seek offset, "
       "mode/owner and sync paths verified");
  return 0;
}
