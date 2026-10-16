#define _GNU_SOURCE 1
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#define CHECK(test) do { \
    if (!(test)) { \
        fprintf(stderr, "newlib-errno: FAIL line=%d errno=%d\n", __LINE__, errno); \
        return 1; \
    } \
} while (0)

int main(void) {
    CHECK(pthread_join(pthread_self(), 0) == EDEADLK);
    CHECK(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, 0) == ENOSYS);
    void *page = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(page != MAP_FAILED);
    CHECK(msync(page, 4096, MS_ASYNC) == -1 && errno == ENOSYS);
    CHECK(munmap(page, 4096) == 0);
    /* Native MemoryProtect rejects an unmapped page. The resulting native
     * error must retain its meaning at the C errno boundary. */
    CHECK(mprotect(page, 4096, PROT_READ) == -1 && errno == ENOMEM);
    fprintf(stderr, "newlib-errno: pass deadlock=%d unsupported=%d overflow=%d\n",
            EDEADLK, ENOSYS, EOVERFLOW);
    return 0;
}
