#define _GNU_SOURCE
#include <semaphore.h>
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

_Static_assert(sizeof(sem_t) == 16, "semaphore ABI size");
_Static_assert(_Alignof(sem_t) == 8, "semaphore ABI alignment");
static sem_t gate;
static atomic_int started, passed;
static void pause_tick(void) { struct timespec delay = {0, 1000000}; nanosleep(&delay, NULL); }
static void debug(const char *message) {
    uint64_t number = 660;
    __asm__ volatile("syscall" : "+a"(number) : "D"((uintptr_t)message), "S"((uint64_t)strlen(message)) : "rcx", "r11", "memory");
}
#define CHECK(x) do { if (!(x)) { char text[128]; snprintf(text, sizeof(text), "native-semaphore: FAIL line=%u errno=%d\n", __LINE__, errno); debug(text); return 1; } } while (0)
static void *consumer(void *unused) {
    (void)unused;
    atomic_fetch_add(&started, 1);
    errno = 123;
    if (sem_wait(&gate) || errno != 123) return (void *)(uintptr_t)1;
    atomic_fetch_add(&passed, 1);
    return NULL;
}
struct shared { sem_t gate; atomic_int started, passed; };
int main(void) {
    int value = -1;
    CHECK(sem_init(&gate, 0, 0) == 0);
    CHECK(sem_trywait(&gate) == -1 && errno == EAGAIN);
    CHECK(sem_getvalue(&gate, &value) == 0 && value == 0);
    CHECK(sem_post(&gate) == 0);
    errno = 123;
    struct timespec bad = {0, 1000000000}, past = {0, 0};
    CHECK(sem_timedwait(&gate, &bad) == 0 && errno == 123);
    CHECK(sem_timedwait(&gate, &bad) == -1 && errno == EINVAL);
    CHECK(sem_timedwait(&gate, &past) == -1 && errno == ETIMEDOUT);
    CHECK(sem_clockwait(&gate, (clockid_t)((UINT64_C(1) << 32) | CLOCK_MONOTONIC), &past) == -1 && errno == EINVAL);
    struct timespec deadline, now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &deadline) == 0);
    deadline.tv_nsec += 50000000;
    if (deadline.tv_nsec >= 1000000000) { ++deadline.tv_sec; deadline.tv_nsec -= 1000000000; }
    CHECK(sem_clockwait(&gate, CLOCK_MONOTONIC, &deadline) == -1 && errno == ETIMEDOUT);
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    CHECK(now.tv_sec > deadline.tv_sec || (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec));
    debug("native-semaphore: counter and deadlines passed\n");

    pthread_t threads[6]; void *result;
    for (int i = 0; i < 6; ++i) CHECK(pthread_create(&threads[i], NULL, consumer, NULL) == 0);
    while (atomic_load(&started) != 6) pause_tick();
    for (int i = 0; i < 6; ++i) CHECK(sem_post(&gate) == 0);
    for (int i = 0; i < 6; ++i) CHECK(pthread_join(threads[i], &result) == 0 && result == NULL);
    CHECK(atomic_load(&passed) == 6);
    CHECK(sem_getvalue(&gate, &value) == 0 && value == 0);
    atomic_store(&started, 0); atomic_store(&passed, 0);
    CHECK(pthread_create(&threads[0], NULL, consumer, NULL) == 0);
    while (!atomic_load(&started)) pause_tick();
    CHECK(pthread_cancel(threads[0]) == 0);
    CHECK(pthread_join(threads[0], &result) == 0 && result == PTHREAD_CANCELED);
    CHECK(atomic_load(&passed) == 0);
    CHECK(sem_post(&gate) == 0 && sem_trywait(&gate) == 0);
    CHECK(sem_destroy(&gate) == 0);
    CHECK(sem_init(&gate, 0, SEM_VALUE_MAX) == 0);
    CHECK(sem_post(&gate) == -1 && errno == EOVERFLOW);
    CHECK(sem_getvalue(&gate, &value) == 0 && value == SEM_VALUE_MAX);
    CHECK(sem_destroy(&gate) == 0);
    debug("native-semaphore: contention and cancellation passed\n");

    const char *path = "/tmp/native-semaphore-shared";
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(fd >= 0 && ftruncate(fd, 4096) == 0);
    struct shared *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(shared != MAP_FAILED && sem_init(&shared->gate, 1, 0) == 0);
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) {
        atomic_store(&shared->started, 1);
        if (sem_wait(&shared->gate)) _exit(1);
        atomic_store(&shared->passed, 1); _exit(0);
    }
    while (!atomic_load(&shared->started)) pause_tick();
    CHECK(atomic_load(&shared->passed) == 0 && sem_post(&shared->gate) == 0);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(atomic_load(&shared->passed) == 1);
    CHECK(sem_getvalue(&shared->gate, &value) == 0 && value == 0);
    CHECK(sem_destroy(&shared->gate) == 0);
    CHECK(munmap(shared, 4096) == 0 && close(fd) == 0 && unlink(path) == 0);
    debug("native-semaphore: PASS SDK ABI, token accounting, errno, timed clocks, cancellation and shared-process wake\n");
    return 0;
}
