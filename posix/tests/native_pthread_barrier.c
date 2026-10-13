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

_Static_assert(sizeof(pthread_barrier_t) == 32, "barrier SDK ABI");
_Static_assert(_Alignof(pthread_barrier_t) == 8, "barrier SDK alignment");
_Static_assert(sizeof(pthread_barrierattr_t) == 8, "barrier attribute SDK ABI");
static pthread_barrier_t barrier;
static atomic_uint values[6], serials;
static atomic_int waiting, returned;
static void debug(const char *message) {
    uint64_t number = 660;
    __asm__ volatile("syscall" : "+a"(number) : "D"((uintptr_t)message), "S"((uint64_t)strlen(message)) : "rcx", "r11", "memory");
}
#define CHECK(x) do { if (!(x)) { char text[128]; snprintf(text, sizeof(text), "native-pthread-barrier: FAIL line=%u errno=%d\n", __LINE__, errno); debug(text); return 1; } } while (0)
static int cross(pthread_barrier_t *gate, atomic_uint *serial_count) {
    int result = pthread_barrier_wait(gate);
    if (result == PTHREAD_BARRIER_SERIAL_THREAD) { atomic_fetch_add(serial_count, 1); return 0; }
    return result;
}
static void *participant(void *argument) {
    unsigned index = (unsigned)(uintptr_t)argument;
    errno = 123;
    for (unsigned round = 1; round <= 100; ++round) {
        atomic_store_explicit(&values[index], round, memory_order_relaxed);
        if (cross(&barrier, &serials) || errno != 123) return (void *)(uintptr_t)1;
        for (unsigned i = 0; i < 6; ++i) if (atomic_load_explicit(&values[i], memory_order_relaxed) != round) return (void *)(uintptr_t)2;
        if (cross(&barrier, &serials)) return (void *)(uintptr_t)3;
    }
    return NULL;
}
static void *cancel_waiter(void *unused) {
    (void)unused; atomic_store(&waiting, 1);
    if (cross(&barrier, &serials)) return (void *)(uintptr_t)1;
    atomic_store(&returned, 1); pthread_testcancel(); return (void *)(uintptr_t)2;
}
struct shared { pthread_barrier_t gate; atomic_uint parent, child, serials; };
int main(void) {
    pthread_barrierattr_t attr; int sharing = -1;
    CHECK(pthread_barrierattr_init(&attr) == 0);
    CHECK(pthread_barrierattr_getpshared(&attr, &sharing) == 0 && sharing == PTHREAD_PROCESS_PRIVATE);
    CHECK(pthread_barrierattr_setpshared(&attr, 99) == EINVAL);
    CHECK(pthread_barrier_init(&barrier, &attr, 0) == EINVAL);
    CHECK(pthread_barrier_init(&barrier, &attr, 1) == 0);
    errno = 123;
    for (unsigned i = 0; i < 100; ++i) CHECK(pthread_barrier_wait(&barrier) == PTHREAD_BARRIER_SERIAL_THREAD && errno == 123);
    CHECK(pthread_barrier_destroy(&barrier) == 0 && pthread_barrier_wait(&barrier) == EINVAL);
    CHECK(pthread_barrier_init(&barrier, &attr, 6) == 0);
    pthread_t threads[6]; void *result;
    for (unsigned i = 0; i < 6; ++i) CHECK(pthread_create(&threads[i], NULL, participant, (void *)(uintptr_t)i) == 0);
    for (unsigned i = 0; i < 6; ++i) CHECK(pthread_join(threads[i], &result) == 0 && result == NULL);
    CHECK(atomic_load(&serials) == 200 && pthread_barrier_destroy(&barrier) == 0);
    CHECK(pthread_barrier_init(&barrier, &attr, 2) == 0);
    CHECK(pthread_create(&threads[0], NULL, cancel_waiter, NULL) == 0);
    struct timespec pause = {0, 1000000};
    while (!atomic_load(&waiting)) CHECK(nanosleep(&pause, NULL) == 0);
    CHECK(pthread_cancel(threads[0]) == 0);
    CHECK(cross(&barrier, &serials) == 0);
    CHECK(pthread_join(threads[0], &result) == 0 && result == PTHREAD_CANCELED && atomic_load(&returned) == 1);
    CHECK(pthread_barrier_destroy(&barrier) == 0);
    debug("native-pthread-barrier: rounds, publication and deferred cancellation passed\n");

    const char *path = "/tmp/native-barrier-shared";
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600); CHECK(fd >= 0 && ftruncate(fd, 4096) == 0);
    struct shared *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(shared != MAP_FAILED);
    CHECK(pthread_barrierattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) == 0);
    CHECK(pthread_barrierattr_getpshared(&attr, &sharing) == 0 && sharing == PTHREAD_PROCESS_SHARED);
    CHECK(pthread_barrier_init(&shared->gate, &attr, 2) == 0 && pthread_barrierattr_destroy(&attr) == 0);
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) {
        for (unsigned round = 1; round <= 100; ++round) {
            atomic_store_explicit(&shared->child, round, memory_order_relaxed);
            if (cross(&shared->gate, &shared->serials) || atomic_load_explicit(&shared->parent, memory_order_relaxed) != round || cross(&shared->gate, &shared->serials)) _exit(1);
        }
        _exit(0);
    }
    for (unsigned round = 1; round <= 100; ++round) {
        atomic_store_explicit(&shared->parent, round, memory_order_relaxed);
        CHECK(cross(&shared->gate, &shared->serials) == 0 && atomic_load_explicit(&shared->child, memory_order_relaxed) == round);
        CHECK(cross(&shared->gate, &shared->serials) == 0);
    }
    int status; CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(atomic_load(&shared->serials) == 200 && pthread_barrier_destroy(&shared->gate) == 0);
    CHECK(munmap(shared, 4096) == 0 && close(fd) == 0 && unlink(path) == 0);
    debug("native-pthread-barrier: PASS SDK ABI, attributes, single serial return, repeated rounds, memory publication, deferred cancellation and process-shared wake\n");
    return 0;
}
