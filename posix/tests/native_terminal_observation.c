#define main pty_master_regression
#include "native_pty_master.c"
#undef main
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>

extern int tcgetwinsize(int, struct winsize *);
extern int tcsetwinsize(int, const struct winsize *);
struct observed_handle {
  uint32_t handle, reserved;
  uint64_t rights;
};
static struct observed_handle prior[256], current[256];
#undef CHECK
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "terminal-observation: FAIL line=%u errno=%d: %s\n",     \
              __LINE__, errno, #x);                                            \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static int64_t observe_native(uint64_t number, uint64_t a, uint64_t b,
                              uint64_t c, uint64_t d, uint64_t e, uint64_t f) {
  register uint64_t r10 __asm__("r10") = d;
  register uint64_t r8 __asm__("r8") = e;
  register uint64_t r9 __asm__("r9") = f;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
static int snapshot(struct observed_handle *items) {
  return (int)observe_native(680, (uintptr_t)items, 256, 0, 0, 0, 0);
}
static int observations(int mode, const char *name,
                        const struct termios *expected,
                        const struct winsize *size) {
  int fd = open(name, mode | O_NOCTTY);
  CHECK(fd >= 0);
  errno = 123;
  CHECK(isatty(fd) == 1 && errno == 123);
  struct termios attrs;
  CHECK(tcgetattr(fd, &attrs) == 0 && errno == 123);
  CHECK(attrs.c_iflag == expected->c_iflag &&
        attrs.c_oflag == expected->c_oflag &&
        attrs.c_lflag == expected->c_lflag &&
        attrs.c_cflag == expected->c_cflag);
  CHECK(!memcmp(attrs.c_cc, expected->c_cc, NCCS));
  struct winsize actual;
  CHECK(tcgetwinsize(fd, &actual) == 0 &&
        !memcmp(&actual, size, sizeof(actual)) && errno == 123);
  CHECK(fpathconf(fd, _PC_MAX_CANON) == 65536 && errno == 123);
  CHECK(fpathconf(fd, _PC_MAX_INPUT) == 65536 && errno == 123);
  CHECK(fpathconf(fd, _PC_VDISABLE) == 0 && errno == 123);
  CHECK(pathconf(name, _PC_MAX_CANON) == 65536 && errno == 123);
  CHECK(pathconf(name, _PC_MAX_INPUT) == 65536 && errno == 123);
  CHECK(pathconf(name, _PC_VDISABLE) == 0 && errno == 123);
  if (mode != O_WRONLY) {
    int baseline = snapshot(prior);
    int alias = dup(fd);
    int total = snapshot(current);
    CHECK(alias >= 0 && baseline > 0 && total == baseline + 1 && total < 256);
    uint32_t source = 0;
    for (int i = 0; i < total; i++) {
      int found = 0;
      for (int j = 0; j < baseline; j++)
        found |= prior[j].handle == current[i].handle;
      if (!found) {
        CHECK(source == 0);
        source = current[i].handle;
      }
    }
    CHECK(source != 0);
    int64_t readonly = observe_native(627, source, 1, 0, 0, 0, 0);
    CHECK(readonly > 0);
    unsigned char encoded[56], old[56];
    CHECK(observe_native(700, readonly, 0x5054595100000002ULL, 0, 0,
                         (uintptr_t)encoded,
                         sizeof(encoded)) == sizeof(encoded));
    CHECK(observe_native(668, source, 0x5054590000000001ULL, 0, 0,
                         (uintptr_t)old, sizeof(old)) == sizeof(old));
    CHECK(!memcmp(old, encoded, sizeof(encoded)));
    struct winsize native_size;
    CHECK(observe_native(700, readonly, 0x5054595100000003ULL, 0, 0,
                         (uintptr_t)&native_size,
                         sizeof(native_size)) == sizeof(native_size));
    CHECK(!memcmp(&native_size, size, sizeof(native_size)));
    unsigned char limits[12];
    CHECK(observe_native(700, readonly, 0x5054595100000004ULL, 0, 0,
                         (uintptr_t)limits, sizeof(limits)) == sizeof(limits));
    const unsigned char expected_limits[12] = {0, 0, 1, 0, 0, 0,
                                               1, 0, 0, 0, 0, 0};
    CHECK(!memcmp(limits, expected_limits, sizeof(limits)));
    CHECK(observe_native(668, readonly, 0x5054590000000002ULL,
                         (uintptr_t)encoded, sizeof(encoded), 0, 0) < 0);
    CHECK(observe_native(700, readonly, 0x5054590000000002ULL,
                         (uintptr_t)encoded, sizeof(encoded), 0, 0) < 0);
    CHECK(observe_native(626, readonly, 0, 0, 0, 0, 0) == 0 &&
          close(alias) == 0);
    CHECK(snapshot(current) == baseline);
  }
  CHECK(close(fd) == 0);
  fprintf(stderr,
          "terminal-observation: PASS access=%d attributes/window query, "
          "terminal limits, rights and cleanup\n",
          mode);
  return 0;
}
int main(void) {
  alarm(60);
  CHECK(pty_master_regression() == 0);
  int master = posix_openpt(O_RDWR | O_NOCTTY);
  CHECK(master >= 0 && grantpt(master) == 0 && unlockpt(master) == 0);
  char name[64];
  CHECK(ptsname_r(master, name, sizeof(name)) == 0);
  struct termios attrs;
  CHECK(tcgetattr(master, &attrs) == 0);
  attrs.c_lflag &= ~ECHO;
  attrs.c_cc[VMIN] = 7;
  CHECK(tcsetattr(master, TCSANOW, &attrs) == 0);
  struct winsize size = {37, 111, 900, 600};
  CHECK(tcsetwinsize(master, &size) == 0);
  for (int mode = O_RDONLY; mode <= O_RDWR; mode++)
    CHECK(observations(mode, name, &attrs, &size) == 0);
  int slave = open(name, O_RDONLY | O_NOCTTY);
  CHECK(slave >= 0);
  unsigned char chunk[4096];
  memset(chunk, 'x', sizeof(chunk));
  long capacity = fpathconf(slave, _PC_MAX_CANON);
  CHECK(capacity == 65536);
  for (long left = capacity - 1; left > 0;) {
    size_t amount = left < (long)sizeof(chunk) ? (size_t)left : sizeof(chunk);
    CHECK(write(master, chunk, amount) == (ssize_t)amount);
    left -= (long)amount;
  }
  CHECK(write(master, "overflow\n", 9) == 9);
  for (long left = capacity; left > 0;) {
    ssize_t got = read(slave, chunk, sizeof(chunk));
    CHECK(got > 0 && got <= left);
    for (ssize_t i = 0; i < got; ++i)
      CHECK(chunk[i] == (left - i == 1 ? '\n' : 'x'));
    left -= got;
  }
  CHECK(close(slave) == 0);
  fprintf(stderr, "terminal-observation: PASS reported canonical capacity "
                  "preserves newline after overflow\n");
  int nonterminal = open("/dev/null", O_RDONLY);
  CHECK(nonterminal >= 0);
  CHECK(fpathconf(nonterminal, _PC_MAX_CANON) == -1 && errno == EINVAL);
  CHECK(close(nonterminal) == 0);
  CHECK(fpathconf(-1, _PC_MAX_CANON) == -1 && errno == EBADF);
  CHECK(pathconf("/dev/null", _PC_MAX_CANON) == -1 && errno == EINVAL);
  CHECK(pathconf("/missing-terminal", _PC_MAX_CANON) == -1 && errno == ENOENT);
  CHECK(pathconf((const char *)(uintptr_t)1, _PC_MAX_CANON) == -1 &&
        errno == EFAULT);
  CHECK(chmod(name, 0) == 0);
  pid_t observer = fork();
  CHECK(observer >= 0);
  if (observer == 0) {
    char inside[64];
    const char *leaf = strrchr(name, '/');
    if (!leaf || snprintf(inside, sizeof(inside), "/%s", leaf + 1) <= 0 ||
        chroot("/dev/pts") != 0 || chdir("/") != 0 || setuid(501) != 0)
      _exit(51);
    errno = 121;
    if (pathconf(inside, _PC_MAX_CANON) != 65536 || errno != 121 ||
        pathconf(inside, _PC_MAX_INPUT) != 65536 || errno != 121 ||
        pathconf(inside, _PC_VDISABLE) != 0 || errno != 121)
      _exit(52);
    if (open(inside, O_RDONLY | O_NOCTTY) != -1 || errno != EACCES)
      _exit(53);
    if (pathconf(name, _PC_MAX_CANON) != -1 || errno != ENOENT)
      _exit(54);
    _exit(0);
  }
  int observed_status;
  CHECK(waitpid(observer, &observed_status, 0) == observer &&
        WIFEXITED(observed_status) && WEXITSTATUS(observed_status) == 0);
  CHECK(chmod(name, 0600) == 0);
  fprintf(stderr, "terminal-observation: PASS pathname owner query needs no "
                  "data permission for mode 000 terminal inside chroot\n");
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    if (setsid() < 0)
      _exit(41);
    int fd = open(name, O_RDONLY | O_NOCTTY);
    if (fd < 0 || tcgetsid(fd) != -1 || errno != ENOTTY)
      _exit(42);
    _exit(close(fd) == 0 ? 0 : 43);
  }
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  fprintf(stderr, "terminal-observation: PASS O_NOCTTY session leader remains "
                  "without controlling terminal\n");
  CHECK(close(master) == 0);
  return 0;
}
