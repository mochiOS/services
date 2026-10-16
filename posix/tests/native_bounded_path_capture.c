/* Open/truncate must reject overlong paths before reading a guard page. */
#define main directory_baseline_main
#include "native_directory_io.c"
#undef main
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>

static sigjmp_buf destination;
static int directory_fd;
static volatile sig_atomic_t expected_fault;
static void fault_handler(int signal) {
  if (signal != SIGSEGV || !expected_fault) {
    static const char message[] =
        "bounded-path: FAIL unexpected guard-page read\n";
    (void)write(2, message, sizeof(message) - 1);
    _exit(91);
  }
  int fd = openat(directory_fd, "nested-\xff", O_CREAT | O_RDWR, 0600);
  if (fd < 0 || close(fd) || unlinkat(directory_fd, "nested-\xff", 0))
    _exit(92);
  siglongjmp(destination, 37);
}
int main(void) {
  char directory[128];
  snprintf(directory, sizeof(directory), "/tmp/bounded-path-%d", (int)getpid());
  CHECK(mkdir(directory, 0700) == 0);
  directory_fd = open(directory, O_RDONLY | O_DIRECTORY);
  CHECK(directory_fd >= 0);
  int fd = openat(directory_fd, "warmup", O_CREAT | O_RDWR, 0600);
  CHECK(fd >= 0 && close(fd) == 0 && unlinkat(directory_fd, "warmup", 0) == 0);
  char *memory = mmap(NULL, 12288, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(memory != MAP_FAILED && mprotect(memory + 8192, 4096, PROT_NONE) == 0);
  char *overlong = memory + 4095;
  memset(overlong, 'x', 4097);
  struct sigaction action = {0};
  action.sa_handler = fault_handler;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  int64_t baseline = native_count();
  for (unsigned round = 0; round < 16; ++round) {
    // No NUL exists before the inaccessible page. These must return a length
    // error, not invoke the signal handler by attempting an unbounded scan.
    errno = 0;
    CHECK(open(overlong, O_RDONLY) == -1 && errno == ENAMETOOLONG);
    errno = 0;
    CHECK(openat(directory_fd, overlong, O_RDONLY) == -1 &&
          errno == ENAMETOOLONG);
    errno = 0;
    CHECK(truncate(overlong, 1) == -1 && errno == ENAMETOOLONG);
    expected_fault = 1;
    int jumped = sigsetjmp(destination, 1);
    if (!jumped) {
      (void)openat(directory_fd, memory + 8192, O_RDONLY);
      CHECK(0);
    }
    CHECK(jumped == 37 && native_count() == baseline);
    expected_fault = 0;
    expected_fault = 1;
    jumped = sigsetjmp(destination, 1);
    if (!jumped) {
      (void)truncate(memory + 8192, 1);
      CHECK(0);
    }
    CHECK(jumped == 37 && native_count() == baseline);
    expected_fault = 0;
  }
  CHECK(munmap(memory, 12288) == 0 && close(directory_fd) == 0 &&
        rmdir(directory) == 0);
  puts("bounded-path: PASS guard-page open/openat/truncate limits, 32 nested "
       "input faults and stable Handle counts");
  return 0;
}
