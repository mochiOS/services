#define _GNU_SOURCE 1
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "cancel-control-copy: FAIL line=%d errno=%d\n", __LINE__, errno); \
        return 1; \
    } \
} while (0)

/* Run on mochiOS: host tests control MemoryCopy, whereas this probe checks
 * actual mapping permissions and the newlib pthread error-number contract. */
int main(void) {
    void *page = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(page != MAP_FAILED);
    int previous = -1;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &previous) == 0);
    for (int readable = 0; readable != 2; ++readable) {
        if (readable)
            CHECK(mprotect(page, 4096, PROT_READ) == 0);
        errno = EDOM;
        CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, page) == EFAULT);
        CHECK(errno == EDOM);
        CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
        CHECK(previous == PTHREAD_CANCEL_ENABLE);
        CHECK(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0);
        CHECK(pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, page) == EFAULT);
        CHECK(errno == EDOM);
        CHECK(pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &previous) == 0);
        CHECK(previous == PTHREAD_CANCEL_DEFERRED);
    }
    CHECK(munmap(page, 4096) == 0);
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, page) == EFAULT);
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &previous) == 0);
    CHECK(previous == PTHREAD_CANCEL_ENABLE);

    unsigned char storage[sizeof(int) + 2];
    memset(storage, 0xa5, sizeof(storage));
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, (int *)(storage + 1)) == 0);
    memcpy(&previous, storage + 1, sizeof(previous));
    CHECK(previous == PTHREAD_CANCEL_ENABLE);
    CHECK(storage[0] == 0xa5 && storage[sizeof(storage) - 1] == 0xa5);
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0);
    fprintf(stderr, "cancel-control-copy: pass\n");
    return 0;
}
