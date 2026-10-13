#include <pthread.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

_Static_assert(sizeof(pthread_spinlock_t) == 4 && _Alignof(pthread_spinlock_t) == 4, "SDK spin ABI");
static pthread_spinlock_t lock;
static unsigned value;
static atomic_int waiting, returned;
static void debug(const char *message) {
    uint64_t number = 660;
    __asm__ volatile("syscall" : "+a"(number) : "D"((uintptr_t)message), "S"((uint64_t)strlen(message)) : "rcx", "r11", "memory");
}
#define CHECK(x) do { if (!(x)) { char text[128]; snprintf(text, sizeof(text), "native-pthread-spin: FAIL line=%u errno=%d\n", __LINE__, errno); debug(text); return 1; } } while (0)
static void *writer(void *unused) {
    (void)unused; errno = 123;
    for (unsigned i = 0; i < 1000; ++i) {
        if (pthread_spin_lock(&lock)) return (void *)(uintptr_t)1;
        ++value;
        if (pthread_spin_unlock(&lock) || errno != 123) return (void *)(uintptr_t)2;
    }
    return NULL;
}
static void *cancel_waiter(void *unused) {
    (void)unused; atomic_store(&waiting, 1);
    if (pthread_spin_lock(&lock)) return (void *)(uintptr_t)1;
    atomic_store(&returned, 1);
    if (pthread_spin_unlock(&lock)) return (void *)(uintptr_t)2;
    pthread_testcancel(); return (void *)(uintptr_t)3;
}
struct shared { pthread_spinlock_t lock; unsigned value; };
int main(void) {
    CHECK(pthread_spin_init(&lock, 99) == EINVAL);
    CHECK(pthread_spin_init(&lock, PTHREAD_PROCESS_PRIVATE) == 0);
    errno = 123;
    CHECK(pthread_spin_lock(&lock) == 0 && errno == 123);
    CHECK(pthread_spin_trylock(&lock) == EBUSY && pthread_spin_destroy(&lock) == EBUSY && errno == 123);
    CHECK(pthread_spin_unlock(&lock) == 0);
    pthread_t threads[6]; void *result;
    for (unsigned i = 0; i < 6; ++i) CHECK(pthread_create(&threads[i], NULL, writer, NULL) == 0);
    for (unsigned i = 0; i < 6; ++i) CHECK(pthread_join(threads[i], &result) == 0 && result == NULL);
    CHECK(value == 6000);
    CHECK(pthread_spin_lock(&lock) == 0);
    CHECK(pthread_create(&threads[0], NULL, cancel_waiter, NULL) == 0);
    struct timespec pause = {0, 1000000};
    while (!atomic_load(&waiting)) CHECK(nanosleep(&pause, NULL) == 0);
    CHECK(pthread_cancel(threads[0]) == 0 && pthread_spin_unlock(&lock) == 0);
    CHECK(pthread_join(threads[0], &result) == 0 && result == PTHREAD_CANCELED && atomic_load(&returned) == 1);
    CHECK(pthread_spin_destroy(&lock) == 0 && pthread_spin_trylock(&lock) == EINVAL);
    CHECK(pthread_spin_init(&lock, PTHREAD_PROCESS_PRIVATE) == 0 && pthread_spin_destroy(&lock) == 0);
    debug("native-pthread-spin: contention, errno and deferred cancellation passed\n");

    const char *path = "/tmp/native-spin-shared";
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600); CHECK(fd >= 0 && ftruncate(fd, 4096) == 0);
    struct shared *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(shared != MAP_FAILED && pthread_spin_init(&shared->lock, PTHREAD_PROCESS_SHARED) == 0);
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) {
        for (unsigned i = 0; i < 1000; ++i) {
            if (pthread_spin_lock(&shared->lock)) _exit(1);
            ++shared->value;
            if (pthread_spin_unlock(&shared->lock)) _exit(2);
        }
        _exit(0);
    }
    for (unsigned i = 0; i < 1000; ++i) {
        CHECK(pthread_spin_lock(&shared->lock) == 0); ++shared->value;
        CHECK(pthread_spin_unlock(&shared->lock) == 0);
    }
    int status; CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(shared->value == 2000 && pthread_spin_destroy(&shared->lock) == 0);
    CHECK(munmap(shared, 4096) == 0 && close(fd) == 0 && unlink(path) == 0);
    debug("native-pthread-spin: PASS SDK ABI, lifecycle, trylock, publication, contention, deferred cancellation and process-shared exclusion\n");
    return 0;
}
