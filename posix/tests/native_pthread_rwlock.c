#define _GNU_SOURCE
#include <pthread.h>
#include <errno.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

_Static_assert(sizeof(pthread_rwlock_t) == 4, "newlib rwlock ABI");
_Static_assert(sizeof(pthread_rwlockattr_t) == 8, "newlib rwlock attribute ABI");
static pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
static atomic_int waiting, returned;
static unsigned data;
static void pause_tick(void) { struct timespec delay = {0, 1000000}; nanosleep(&delay, NULL); }
static void debug(const char *message) {
    uint64_t number = 660;
    __asm__ volatile("syscall" : "+a"(number) : "D"((uintptr_t)message), "S"((uint64_t)strlen(message)) : "rcx", "r11", "memory");
}
#define CHECK(x) do { if (!(x)) { char text[128]; snprintf(text, sizeof(text), "native-pthread-rwlock: FAIL line=%u errno=%d\n", __LINE__, errno); debug(text); return 1; } } while (0)
static void *writer(void *unused) {
    (void)unused;
    for (unsigned i = 0; i < 100; ++i) {
        if (pthread_rwlock_wrlock(&lock)) return (void *)(uintptr_t)1;
        ++data;
        if (pthread_rwlock_unlock(&lock)) return (void *)(uintptr_t)2;
    }
    return NULL;
}
static void *waiter(void *unused) {
    (void)unused; atomic_store(&waiting, 1);
    if (pthread_rwlock_rdlock(&lock)) return (void *)(uintptr_t)1;
    atomic_store(&returned, 1);
    if (pthread_rwlock_unlock(&lock)) return (void *)(uintptr_t)2;
    pthread_testcancel(); return (void *)(uintptr_t)3;
}
struct shared { pthread_rwlock_t lock; atomic_int started, passed; };
int main(void) {
    pthread_rwlockattr_t attr; int sharing = -1;
    CHECK(pthread_rwlockattr_init(&attr) == 0);
    CHECK(pthread_rwlockattr_getpshared(&attr, &sharing) == 0 && sharing == PTHREAD_PROCESS_PRIVATE);
    CHECK(pthread_rwlockattr_setpshared(&attr, 99) == EINVAL);
    CHECK(pthread_rwlock_rdlock(&lock) == 0 && pthread_rwlock_rdlock(&lock) == 0);
    CHECK(pthread_rwlock_trywrlock(&lock) == EBUSY && pthread_rwlock_destroy(&lock) == EBUSY);
    CHECK(pthread_rwlock_unlock(&lock) == 0 && pthread_rwlock_unlock(&lock) == 0);
    CHECK(pthread_rwlock_wrlock(&lock) == 0);
    CHECK(pthread_rwlock_tryrdlock(&lock) == EBUSY && pthread_rwlock_trywrlock(&lock) == EBUSY);
    struct timespec past = {0, 0}, bad = {0, 1000000000};
    errno = 123;
    CHECK(pthread_rwlock_timedrdlock(&lock, &past) == ETIMEDOUT && errno == 123);
    CHECK(pthread_rwlock_timedwrlock(&lock, &bad) == EINVAL && errno == 123);
    CHECK(pthread_rwlock_clockrdlock(&lock, CLOCK_MONOTONIC, &past) == ETIMEDOUT);
    CHECK(pthread_rwlock_clockwrlock(&lock, (clockid_t)((UINT64_C(1) << 32) | CLOCK_MONOTONIC), &past) == EINVAL);
    CHECK(pthread_rwlock_unlock(&lock) == 0);
    CHECK(pthread_rwlock_timedwrlock(&lock, &bad) == 0 && pthread_rwlock_unlock(&lock) == 0);
    CHECK(pthread_rwlock_clockrdlock(&lock, CLOCK_MONOTONIC, &past) == 0 && pthread_rwlock_unlock(&lock) == 0);
    pthread_t threads[6]; void *result;
    for (unsigned i = 0; i < 6; ++i) CHECK(pthread_create(&threads[i], NULL, writer, NULL) == 0);
    for (unsigned i = 0; i < 6; ++i) CHECK(pthread_join(threads[i], &result) == 0 && result == NULL);
    CHECK(data == 600);
    CHECK(pthread_rwlock_wrlock(&lock) == 0);
    CHECK(pthread_create(&threads[0], NULL, waiter, NULL) == 0);
    while (!atomic_load(&waiting)) pause_tick();
    CHECK(pthread_cancel(threads[0]) == 0);
    CHECK(pthread_rwlock_unlock(&lock) == 0);
    CHECK(pthread_join(threads[0], &result) == 0 && result == PTHREAD_CANCELED && atomic_load(&returned) == 1);
    CHECK(pthread_rwlock_destroy(&lock) == 0 && pthread_rwlock_tryrdlock(&lock) == EINVAL);
    CHECK(pthread_rwlock_init(&lock, &attr) == 0 && pthread_rwlock_destroy(&lock) == 0);

    const char *path = "/tmp/native-rwlock-shared";
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600); CHECK(fd >= 0 && ftruncate(fd, 4096) == 0);
    struct shared *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(shared != MAP_FAILED);
    CHECK(pthread_rwlockattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) == 0);
    CHECK(pthread_rwlock_init(&shared->lock, &attr) == 0);
    CHECK(pthread_rwlockattr_destroy(&attr) == 0);
    CHECK(pthread_rwlock_wrlock(&shared->lock) == 0);
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) {
        atomic_store(&shared->started, 1);
        if (pthread_rwlock_rdlock(&shared->lock)) _exit(1);
        atomic_store(&shared->passed, 1);
        _exit(pthread_rwlock_unlock(&shared->lock) != 0);
    }
    while (!atomic_load(&shared->started)) pause_tick();
    CHECK(atomic_load(&shared->passed) == 0);
    CHECK(pthread_rwlock_unlock(&shared->lock) == 0);
    int status; CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(atomic_load(&shared->passed) == 1 && pthread_rwlock_destroy(&shared->lock) == 0);
    CHECK(munmap(shared, 4096) == 0 && close(fd) == 0 && unlink(path) == 0);
    debug("native-pthread-rwlock: PASS ABI, attributes, reader recursion, writer contention, timed clocks, deferred cancellation and shared-process wake\n");
    return 0;
}
