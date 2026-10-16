#define main mapping_budget_regressions
#include "native_mapping_budget.c"
#undef main
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

static _Atomic(unsigned) mr_ready, mr_go;
static _Atomic(unsigned) *mr_remote;
static void *mr_observe(void *unused) {
  (void)unused;
  unsigned initial = atomic_load(mr_remote);
  atomic_store_explicit(&mr_ready, 1, memory_order_release);
  while (!atomic_load_explicit(&mr_go, memory_order_acquire)) sched_yield();
  return initial != 0x1234 ? (void *)1 : atomic_load(mr_remote) == 0 ? NULL : (void *)2;
}
int main(void) {
  unsigned char *base = mmap(NULL, 12288, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(base != MAP_FAILED);
  base[0] = 11; base[4096] = 22; base[8192] = 33;
  CHECK(mmap(base + 4096, 4096, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == base + 4096);
  CHECK(base[0] == 11 && base[4096] == 0 && base[8192] == 33);
  base[4096] = 44;
  CHECK(mmap(base + 4096, 4096, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_FIXED, -1, 0) == MAP_FAILED && errno == EBADF);
  CHECK(base[4096] == 44);
  CHECK(mmap(base + 4097, 4096, PROT_READ,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED && errno == EINVAL);
  CHECK(base[4096] == 44);
  CHECK(mmap(base + 4096, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED && errno == EINVAL);
  CHECK(base[4096] == 44);
  uint64_t used = mb_usage();
  CHECK(used != UINT64_MAX);
  struct mb_request request = {.address = (uintptr_t)(base + 4096), .length = 4096,
      .access = 3, .options = 1 | 4, .ceiling = used};
  CHECK(mb_call(695, (uintptr_t)&request, sizeof(request), 0) == (intptr_t)(base + 4096));
  CHECK(base[4096] == 0);
  base[4096] = 55;
  request.ceiling = used - 4096;
  CHECK(mb_call(695, (uintptr_t)&request, sizeof(request), 0) == -ENOMEM);
  CHECK(base[4096] == 55);
  request.ceiling = UINT64_MAX;
  request.options = 4;
  CHECK(mb_call(695, (uintptr_t)&request, sizeof(request), 0) == -EINVAL);
  CHECK(base[4096] == 55);
  mr_remote = (_Atomic(unsigned) *)(base + 4096);
  atomic_store(mr_remote, 0x1234);
  pthread_t observer_thread;
  void *observer_result;
  CHECK(pthread_create(&observer_thread, NULL, mr_observe, NULL) == 0);
  while (!atomic_load_explicit(&mr_ready, memory_order_acquire)) sched_yield();
  CHECK(mmap(base + 4096, 4096, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == base + 4096);
  atomic_store_explicit(&mr_go, 1, memory_order_release);
  CHECK(pthread_join(observer_thread, &observer_result) == 0 && observer_result == NULL);
  CHECK(munmap(base, 12288) == 0);

  const char *path = "/tmp/posix-fixed-replacement";
  int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
  CHECK(fd >= 0 && ftruncate(fd, 12288) == 0);
  CHECK(pwrite(fd, "a", 1, 0) == 1 && pwrite(fd, "b", 1, 4096) == 1 &&
        pwrite(fd, "c", 1, 8192) == 1);
  base = mmap(NULL, 12288, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  CHECK(base != MAP_FAILED && base[0] == 'a' && base[4096] == 'b' && base[8192] == 'c');
  base[4096 + 17] = 'q';
  CHECK(mmap(base + 4096, 4096, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_FIXED, fd, 8192) == base + 4096);
  CHECK(base[0] == 'a' && base[4096] == 'c' && base[8192] == 'c');
  char byte;
  CHECK(pread(fd, &byte, 1, 4096 + 17) == 1 && byte == 'q');
  base[4096] = 'x';
  CHECK(base[8192] == 'c' && pread(fd, &byte, 1, 8192) == 1 && byte == 'c');
  int readonly = open(path, O_RDONLY);
  CHECK(readonly >= 0);
  CHECK(mmap(base + 4096, 4096, PROT_READ | PROT_WRITE,
             MAP_SHARED | MAP_FIXED, readonly, 0) == MAP_FAILED && errno == EACCES);
  CHECK(base[4096] == 'x');
  CHECK(close(readonly) == 0 && munmap(base, 12288) == 0 && close(fd) == 0 && unlink(path) == 0);
  CHECK(mapping_budget_regressions() == 0);
  puts("mapping-replace: PASS anonymous/file partial replacement, offsets, writeback, "
       "private isolation, authority failures, projected ceiling and cross-thread translation refresh");
  return 0;
}
