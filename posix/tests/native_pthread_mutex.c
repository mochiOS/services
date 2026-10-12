#define _GNU_SOURCE 1
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(pthread_mutex_t) == 32, "inline mutex ABI");
_Static_assert(_Alignof(pthread_mutex_t) == 8, "mutex alignment");
_Static_assert(sizeof(pthread_mutexattr_t) == 12, "attribute ABI");

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned counter;
static _Atomic unsigned ready, acquired, cleaned;

static void debug(const char *message) {
    uint64_t number = 660;
    __asm__ volatile("syscall" : "+a"(number)
        : "D"((uintptr_t)message), "S"((uint64_t)strlen(message)) : "rcx", "r11", "memory");
}
#define CHECK(condition) do { if (!(condition)) { \
    char message[128]; snprintf(message, sizeof(message), \
    "native-pthread-mutex: FAIL line=%u errno=%d\n", __LINE__, errno); \
    debug(message); return 1; \
} } while (0)

static void *increment(void *unused) {
    (void)unused;
    for (unsigned n = 0; n < 2000; ++n) {
        if (pthread_mutex_lock(&mutex)) return (void *)1;
        ++counter;
        if (pthread_mutex_unlock(&mutex)) return (void *)2;
    }
    return NULL;
}

static void cleanup(void *unused) { (void)unused; atomic_store(&cleaned, 1); }
static void *cancel_waiter(void *unused) {
    (void)unused;
    pthread_cleanup_push(cleanup, NULL);
    atomic_store(&ready, 1);
    if (pthread_mutex_lock(&mutex)) return (void *)1;
    atomic_store(&acquired, 1);
    if (pthread_mutex_unlock(&mutex)) return (void *)2;
    pthread_testcancel(); // Pending cancellation must wait for this point.
    pthread_cleanup_pop(0);
    return (void *)3;
}

static int await_flag(_Atomic unsigned *flag) {
    for (unsigned n = 0; n < 2000; ++n) {
        if (atomic_load(flag)) return 1;
        struct timespec delay = {0, 1000000};
        if (nanosleep(&delay, NULL)) return 0;
    }
    return 0;
}

int main(void) {
    errno = 123;
    CHECK(pthread_mutex_lock(&mutex) == 0 && errno == 123);
    CHECK(pthread_mutex_trylock(&mutex) == EBUSY && errno == 123);
    CHECK(pthread_mutex_destroy(&mutex) == EBUSY);
    CHECK(pthread_mutex_unlock(&mutex) == 0 && errno == 123);
    pthread_mutexattr_t attr;
    int kind = -1, shared = -1;
    CHECK(pthread_mutexattr_init(&attr) == 0);
    CHECK(pthread_mutexattr_gettype(&attr, &kind) == 0 && kind == PTHREAD_MUTEX_DEFAULT);
    CHECK(pthread_mutexattr_getpshared(&attr, &shared) == 0 && shared == PTHREAD_PROCESS_PRIVATE);
    CHECK(pthread_mutexattr_settype(&attr, 99) == EINVAL);
    CHECK(pthread_mutexattr_setpshared(&attr, 99) == EINVAL);
    CHECK(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK) == 0);
    pthread_mutex_t dynamic;
    CHECK(pthread_mutex_init(&dynamic, &attr) == 0);
    CHECK(pthread_mutex_lock(&dynamic) == 0);
    CHECK(pthread_mutex_lock(&dynamic) == EDEADLK);
    CHECK(pthread_mutex_trylock(&dynamic) == EBUSY);
    CHECK(pthread_mutex_unlock(&dynamic) == 0);
    CHECK(pthread_mutex_unlock(&dynamic) == EPERM);
    CHECK(pthread_mutex_destroy(&dynamic) == 0);
    CHECK(pthread_mutex_lock(&dynamic) == EINVAL);
    CHECK(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) == 0);
    CHECK(pthread_mutex_init(&dynamic, &attr) == 0);
    CHECK(pthread_mutex_lock(&dynamic) == 0);
    dynamic.depth = UINT32_MAX; // Inject the recursion limit without billions of calls.
    CHECK(pthread_mutex_trylock(&dynamic) == EAGAIN && dynamic.depth == UINT32_MAX);
    dynamic.depth = 1;
    CHECK(pthread_mutex_unlock(&dynamic) == 0);
    for (unsigned n = 0; n < 4; ++n) CHECK(pthread_mutex_lock(&dynamic) == 0);
    for (unsigned n = 0; n < 4; ++n) CHECK(pthread_mutex_unlock(&dynamic) == 0);
    CHECK(pthread_mutex_destroy(&dynamic) == 0);
    pthread_t threads[4];
    for (unsigned n = 0; n < 4; ++n) CHECK(pthread_create(&threads[n], NULL, increment, NULL) == 0);
    for (unsigned n = 0; n < 4; ++n) {
        void *result = (void *)99;
        CHECK(pthread_join(threads[n], &result) == 0 && result == NULL);
    }
    CHECK(counter == 8000);
    CHECK(pthread_mutex_lock(&mutex) == 0);
    pthread_t canceled;
    CHECK(pthread_create(&canceled, NULL, cancel_waiter, NULL) == 0);
    CHECK(await_flag(&ready));
    CHECK(pthread_cancel(canceled) == 0);
    struct timespec delay = {0, 20000000};
    CHECK(nanosleep(&delay, NULL) == 0);
    CHECK(!atomic_load(&acquired) && !atomic_load(&cleaned));
    CHECK(pthread_mutex_unlock(&mutex) == 0);
    CHECK(await_flag(&cleaned));
    void *result = NULL;
    CHECK(pthread_join(canceled, &result) == 0 && result == PTHREAD_CANCELED && atomic_load(&acquired));
    CHECK(pthread_mutex_trylock(&mutex) == 0);
    CHECK(pthread_mutex_unlock(&mutex) == 0 && pthread_mutex_destroy(&mutex) == 0);

    // Independent address spaces must observe the same inline mutex state.
    struct shared_state { pthread_mutex_t mutex; unsigned value; };
    struct shared_state *mapped = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(mapped != MAP_FAILED);
    CHECK(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL) == 0);
    CHECK(pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) == 0);
    CHECK(pthread_mutex_init(&mapped->mutex, &attr) == 0);
    CHECK(pthread_mutex_lock(&mapped->mutex) == 0);
    int pipefd[2];
    CHECK(pipe(pipefd) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        if (pthread_mutex_trylock(&mapped->mutex) != EBUSY) _exit(2);
        if (write(pipefd[1], "r", 1) != 1) _exit(5);
        if (pthread_mutex_lock(&mapped->mutex) != 0) _exit(3);
        mapped->value = 1234;
        if (pthread_mutex_unlock(&mapped->mutex) != 0) _exit(4);
        _exit(0);
    }
    char byte = 0;
    CHECK(read(pipefd[0], &byte, 1) == 1 && byte == 'r');
    CHECK(nanosleep(&delay, NULL) == 0);
    CHECK(pthread_mutex_unlock(&mapped->mutex) == 0);
    int status = -1;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(pthread_mutex_lock(&mapped->mutex) == 0 && mapped->value == 1234);
    CHECK(pthread_mutex_unlock(&mapped->mutex) == 0 && pthread_mutex_destroy(&mapped->mutex) == 0);
    CHECK(munmap(mapped, 4096) == 0);
    CHECK(close(pipefd[0]) == 0 && close(pipefd[1]) == 0);
    CHECK(pthread_mutexattr_destroy(&attr) == 0);
    CHECK(pthread_mutexattr_gettype(&attr, &kind) == EINVAL);
    debug("native-pthread-mutex: PASS ABI, ownership, contention, non-cancellation and cross-process shared lock\n");
    return 0;
}
