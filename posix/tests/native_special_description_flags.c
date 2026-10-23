/* Exercise regular-file regressions and nonterminal device flags through the
 * same real runtime. No new filesystem/service test implementation is used. */
#define main regular_flags_regression
#include "native_file_description_flags.c"
#undef main
#undef CHECK
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "special-flags: FAIL line=%u errno=%d: %s\n", __LINE__,  \
              errno, #x);                                                      \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static int64_t special_call6(uint64_t number, uint64_t a, uint64_t b,
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

static int special_case(int mode) {
  int baseline = count(before);
  CHECK(baseline > 0 && baseline < 256);
  int fd = open("/dev/null", mode | O_CLOEXEC);
  CHECK(fd >= 0);
  struct stat status;
  CHECK(fstat(fd, &status) == 0 && S_ISCHR(status.st_mode));
  CHECK(isatty(fd) == 0);
  int total = count(after);
  CHECK(total == baseline + 1);
  uint32_t source = 0;
  for (int i = 0; i < total; i++) {
    int found = 0;
    for (int j = 0; j < baseline; j++)
      found |= after[i].handle == before[j].handle;
    if (!found) {
      CHECK(source == 0);
      source = after[i].handle;
    }
  }
  CHECK(source != 0);
  int alias = dup(fd), independent = open("/dev/null", mode);
  CHECK(alias >= 0 && independent >= 0);
  errno = 123;
  CHECK(fcntl(fd, F_SETFL, O_APPEND | O_NONBLOCK) == 0 && errno == 123);
  CHECK((fcntl(alias, F_GETFL) & (O_ACCMODE | O_APPEND | O_NONBLOCK)) ==
        (mode | O_APPEND | O_NONBLOCK));
  CHECK((fcntl(independent, F_GETFL) & (O_APPEND | O_NONBLOCK)) == 0);
  CHECK(fcntl(fd, F_GETFD) == FD_CLOEXEC && fcntl(alias, F_GETFD) == 0);
  CHECK(__mochios_fd_set_nonblocking(alias, 0) == 0);
  CHECK((fcntl(fd, F_GETFL) & (O_APPEND | O_NONBLOCK)) == O_APPEND);
  if (mode != O_WRONLY) {
    // READ only, no CONTROL, TRANSFER or duplicate right. This must be an
    // actual read-only native query; a control request cannot borrow authority.
    int64_t query_reference = native(627, source, 1, 0);
    CHECK(query_reference > 0);
    uint32_t flags = 0;
    uint64_t get = 0x47414c463153464dULL; /* MFS1FLAG, LE */
    CHECK(special_call6(700, (uint64_t)query_reference, get, 0, 0,
                        (uintptr_t)&flags, 4) == 4);
    CHECK(flags == 1); /* filesystem OPEN_STATUS_APPEND */
    CHECK(special_call6(668, (uint64_t)query_reference, get, 0, 0,
                        (uintptr_t)&flags, 4) < 0);
    CHECK(native(626, (uint64_t)query_reference, 0, 0) == 0);
    char byte = 'x';
    CHECK(read(fd, &byte, 1) == 0 && byte == 'x');
  }
  if (mode != O_RDONLY)
    CHECK(write(alias, "discarded", 9) == 9);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0)
    _exit(fcntl(alias, F_SETFL, O_NONBLOCK) == 0 ? 0 : 37);
  int waited;
  CHECK(waitpid(child, &waited, 0) == child && WIFEXITED(waited) &&
        WEXITSTATUS(waited) == 0);
  CHECK((fcntl(fd, F_GETFL) & (O_ACCMODE | O_APPEND | O_NONBLOCK)) ==
        (mode | O_NONBLOCK));
  CHECK(close(alias) == 0 && close(independent) == 0 && close(fd) == 0);
  CHECK(count(after) == baseline);
  fprintf(stderr,
          "special-flags: PASS access=%d alias/fork sharing, atomic mask, "
          "rights and cleanup\n",
          mode);
  return 0;
}

int main(void) {
  if (regular_flags_regression())
    return 1;
  int warm = open("/dev/null", O_RDWR);
  CHECK(warm >= 0 && close(warm) == 0);
  for (int mode = O_RDONLY; mode <= O_RDWR; mode++)
    CHECK(special_case(mode) == 0);
  return 0;
}
