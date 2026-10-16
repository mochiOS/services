/* Keep the full shared-memory fork/exec regression and add repeated ownership
 * checks on the newly scoped native receive envelope. */
#define main shared_memory_regression_main
#include "native_posix_shared_memory.c"
#undef main
#include <stdint.h>
#include <sys/resource.h>

static int64_t native_count(void) {
  uint64_t number = 680;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"((uint64_t)0), "S"((uint64_t)0), "d"((uint64_t)0)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
int main(int argc, char **argv) {
  if (argc == 5)
    return shared_memory_regression_main(argc, argv);
  CHECK(shared_memory_regression_main(argc, argv) == 0);
  const char *name = "/mapping-backing-scope";
  int writer = shm_open(name, O_CREAT | O_EXCL | O_RDWR, 0600);
  CHECK(writer >= 0 && ftruncate(writer, 8192) == 0);
  int reader = shm_open(name, O_RDONLY, 0);
  CHECK(reader >= 0);
  char *warm = mmap(NULL, 4096, PROT_READ, MAP_SHARED, reader, 0);
  CHECK(warm != MAP_FAILED && munmap(warm, 4096) == 0);
  int64_t baseline = native_count();
  for (unsigned round = 0; round < 16; ++round) {
    char *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED,
                        writer, 4096);
    CHECK(shared != MAP_FAILED && native_count() == baseline);
    shared[0] = (char)round;
    char *private = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE,
                         reader, 4096);
    CHECK(private != MAP_FAILED && private[0] == (char)round &&
          native_count() == baseline);
    private[0] = 99;
    CHECK(shared[0] == (char)round);
    CHECK(munmap(private, 4096) == 0 && munmap(shared, 4096) == 0);
    errno = 0;
    CHECK(mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, reader, 0) ==
              MAP_FAILED && errno == EACCES);
    struct rlimit previous;
    CHECK(getrlimit(RLIMIT_AS, &previous) == 0);
    struct rlimit tiny = previous;
    tiny.rlim_cur = 1;
    CHECK(setrlimit(RLIMIT_AS, &tiny) == 0);
    errno = 0;
    CHECK(mmap(NULL, 4096, PROT_READ, MAP_SHARED, reader, 0) == MAP_FAILED &&
          errno == ENOMEM);
    CHECK(setrlimit(RLIMIT_AS, &previous) == 0);
    CHECK(native_count() == baseline);
  }
  char *retained = mmap(NULL, 4096, PROT_READ, MAP_SHARED, reader, 4096);
  CHECK(retained != MAP_FAILED && shm_unlink(name) == 0);
  CHECK(close(writer) == 0 && close(reader) == 0 && retained[0] == 15);
  CHECK(munmap(retained, 4096) == 0 && native_count() == baseline - 2);
  puts("mapping-backing-scope: PASS 16 rounds, read/write attenuation, "
       "private COW, map admission failure and received Handle recovery");
  return 0;
}
