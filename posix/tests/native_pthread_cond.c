#define _GNU_SOURCE 1
/* Isolated Compositor-slot probe. Its test manifest must declare
 * system.time.read and its built-in verification record must match it. */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(pthread_cond_t) == 24 && _Alignof(pthread_cond_t) == 8, "condition ABI");
_Static_assert(sizeof(pthread_condattr_t) == 12, "attribute ABI");
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static _Atomic unsigned ready[4], returned[4], cleaned, bad_cleanup, handled;
static unsigned mode, allowed;

static void debug(const char *message) {
    uint64_t number = 660;
    __asm__ volatile("syscall" : "+a"(number)
        : "D"((uintptr_t)message), "S"((uint64_t)strlen(message)) : "rcx", "r11", "memory");
}
#define CHECK(condition) do { if (!(condition)) { \
    char message[128]; snprintf(message, sizeof(message), \
    "native-pthread-cond: FAIL mode=%u line=%u errno=%d\n", mode, __LINE__, errno); \
    debug(message); return 1; \
} } while (0)

static int await_flag(_Atomic unsigned *flag) {
    for (unsigned n = 0; n < 2000; ++n) {
        if (atomic_load(flag)) return 1;
        struct timespec delay = {0, 1000000};
        if (nanosleep(&delay, NULL)) return 0;
    }
    return 0;
}
static struct timespec future(clockid_t clock, long duration) {
    struct timespec time;
    if (clock_gettime(clock, &time)) {
        char message[96];
        snprintf(message, sizeof(message), "native-pthread-cond: clock read failed clock=%llu errno=%d\n", (unsigned long long)clock, errno);
        debug(message);
        return (struct timespec){-1, -1};
    }
    time.tv_nsec += duration;
    time.tv_sec += time.tv_nsec / 1000000000;
    time.tv_nsec %= 1000000000;
    return time;
}
static void cleanup(void *unused) {
    (void)unused;
    if (pthread_mutex_unlock(&mutex)) atomic_store(&bad_cleanup, 1);
    atomic_store(&cleaned, 1);
}
static void caught(int signal) { (void)signal; atomic_fetch_add(&handled, 1); }
static void *waiter(void *argument) {
    unsigned index = (unsigned)(uintptr_t)argument;
    if (mode == 3 && pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL)) return (void *)1;
    if (pthread_mutex_lock(&mutex)) return (void *)2;
    int result = 0;
    pthread_cleanup_push(cleanup, NULL);
    atomic_store(&ready[index], 1);
    while (!allowed) {
        if (mode == 1) {
            struct timespec time = future(CLOCK_REALTIME, 500000000);
            time.tv_sec += 5;
            result = pthread_cond_timedwait(&cond, &mutex, &time);
        } else if (mode == 2) {
            struct timespec time = future(CLOCK_MONOTONIC, 500000000);
            time.tv_sec += 5;
            result = pthread_cond_clockwait(&cond, &mutex, CLOCK_MONOTONIC, &time);
        } else result = pthread_cond_wait(&cond, &mutex);
        if (result) {
            char message[128];
            snprintf(message, sizeof(message), "native-pthread-cond: waiter mode=%u index=%u result=%d\n", mode, index, result);
            debug(message);
            break;
        }
    }
    atomic_store(&returned[index], 1);
    if (mode == 3) {
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        pthread_testcancel();
    }
    pthread_cleanup_pop(0);
    if (pthread_mutex_unlock(&mutex)) return (void *)3;
    return (void *)(intptr_t)result;
}
static void reset(void) {
    allowed = 0;
    for (unsigned n = 0; n < 4; ++n) { atomic_store(&ready[n], 0); atomic_store(&returned[n], 0); }
    atomic_store(&cleaned, 0); atomic_store(&bad_cleanup, 0);
}
int main(void) {
    pthread_condattr_t attr;
    clockid_t clock = (clockid_t)-1;
    int shared = -1;
    CHECK(pthread_condattr_init(&attr) == 0);
    CHECK(pthread_condattr_getclock(&attr, &clock) == 0 && clock == CLOCK_REALTIME);
    CHECK(pthread_condattr_getpshared(&attr, &shared) == 0 && shared == PTHREAD_PROCESS_PRIVATE);
    CHECK(pthread_condattr_setclock(&attr, CLOCK_THREAD_CPUTIME_ID) == EINVAL);
    CHECK(pthread_condattr_setpshared(&attr, 99) == EINVAL);
    struct timespec delay = {0, 20000000};
    for (mode = 0; mode < 3; ++mode) {
        reset();
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, waiter, NULL) == 0);
        CHECK(await_flag(&ready[0]));
        CHECK(pthread_mutex_lock(&mutex) == 0); // Wait atomically released it.
        CHECK(pthread_cond_destroy(&cond) == EBUSY);
        allowed = 1;
        CHECK(pthread_cond_signal(&cond) == 0);
        CHECK(pthread_mutex_unlock(&mutex) == 0);
        CHECK(await_flag(&returned[0]));
        void *result = (void *)99;
        CHECK(pthread_join(thread, &result) == 0 && result == NULL && atomic_load(&returned[0]));
    }
    debug("native-pthread-cond: notify variants passed\n");
    for (mode = 0; mode < 4; ++mode) {
        reset();
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, waiter, NULL) == 0);
        CHECK(await_flag(&ready[0]));
        CHECK(pthread_mutex_lock(&mutex) == 0);
        CHECK(pthread_cancel(thread) == 0);
        CHECK(nanosleep(&delay, NULL) == 0);
        CHECK(!atomic_load(&cleaned) && !atomic_load(&returned[0]));
        if (mode == 3) { allowed = 1; CHECK(pthread_cond_signal(&cond) == 0); }
        CHECK(pthread_mutex_unlock(&mutex) == 0);
        CHECK(await_flag(&cleaned));
        void *result = NULL;
        CHECK(pthread_join(thread, &result) == 0 && result == PTHREAD_CANCELED && !atomic_load(&bad_cleanup));
        CHECK(atomic_load(&returned[0]) == (mode == 3));
        CHECK(pthread_mutex_trylock(&mutex) == 0 && pthread_mutex_unlock(&mutex) == 0);
        CHECK(pthread_cond_destroy(&cond) == 0 && pthread_cond_init(&cond, NULL) == 0);
    }
    debug("native-pthread-cond: cancellation variants passed\n");
    // An already signaled thread canceled during mutex reacquisition must
    // pass its notification to the other admitted waiter.
    mode = 0; reset();
    pthread_t first, second;
    CHECK(pthread_create(&first, NULL, waiter, NULL) == 0 && await_flag(&ready[0]));
    CHECK(pthread_mutex_lock(&mutex) == 0 && pthread_mutex_unlock(&mutex) == 0);
    CHECK(pthread_create(&second, NULL, waiter, (void *)1) == 0 && await_flag(&ready[1]));
    CHECK(pthread_mutex_lock(&mutex) == 0);
    allowed = 1;
    CHECK(pthread_cond_signal(&cond) == 0);
    CHECK(pthread_cancel(first) == 0);
    CHECK(nanosleep(&delay, NULL) == 0);
    CHECK(pthread_mutex_unlock(&mutex) == 0);
    CHECK(await_flag(&cleaned) && await_flag(&returned[1]));
    void *result = NULL;
    CHECK(pthread_join(first, &result) == 0 && result == PTHREAD_CANCELED && !atomic_load(&bad_cleanup));
    CHECK(pthread_join(second, &result) == 0 && result == NULL);
    debug("native-pthread-cond: replacement signal passed\n");

    reset();
    pthread_t threads[4];
    for (unsigned n = 0; n < 4; ++n) CHECK(pthread_create(&threads[n], NULL, waiter, (void *)(uintptr_t)n) == 0);
    for (unsigned n = 0; n < 4; ++n) CHECK(await_flag(&ready[n]));
    CHECK(pthread_mutex_lock(&mutex) == 0);
    allowed = 1;
    CHECK(pthread_cond_broadcast(&cond) == 0 && pthread_mutex_unlock(&mutex) == 0);
    for (unsigned n = 0; n < 4; ++n) CHECK(await_flag(&returned[n]) && pthread_join(threads[n], &result) == 0 && result == NULL);
    debug("native-pthread-cond: broadcast passed\n");

    reset();
    struct sigaction action = {0}, previous_action; action.sa_handler = caught; sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, &action, &previous_action) == 0);
    CHECK(pthread_create(&first, NULL, waiter, NULL) == 0 && await_flag(&ready[0]));
    CHECK(pthread_kill(first, SIGUSR1) == 0 && await_flag(&handled));
    CHECK(!atomic_load(&returned[0]));
    CHECK(pthread_mutex_lock(&mutex) == 0);
    allowed = 1;
    CHECK(pthread_cond_signal(&cond) == 0 && pthread_mutex_unlock(&mutex) == 0);
    CHECK(pthread_join(first, &result) == 0 && result == NULL);
    CHECK(sigaction(SIGUSR1, &previous_action, NULL) == 0);
    debug("native-pthread-cond: handler restart passed\n");

    for (mode = 4; mode < 7; ++mode) {
        CHECK(pthread_cond_destroy(&cond) == 0);
        CHECK(pthread_condattr_setclock(&attr, mode == 5 ? CLOCK_MONOTONIC : CLOCK_REALTIME) == 0);
        CHECK(pthread_cond_init(&cond, &attr) == 0);
        CHECK(pthread_mutex_lock(&mutex) == 0);
        struct timespec time = future(mode == 4 ? CLOCK_REALTIME : CLOCK_MONOTONIC, 20000000);
        errno = 123;
        int err = mode == 6 ? pthread_cond_clockwait(&cond, &mutex, CLOCK_MONOTONIC, &time)
            : pthread_cond_timedwait(&cond, &mutex, &time);
        CHECK(err == ETIMEDOUT && errno == 123);
        CHECK(pthread_mutex_trylock(&mutex) == EBUSY);
        time.tv_nsec = 1000000000;
        CHECK(pthread_cond_timedwait(&cond, &mutex, &time) == EINVAL);
        CHECK(pthread_mutex_unlock(&mutex) == 0);
    }
    debug("native-pthread-cond: clocks passed\n");
    // Shared conditions use inline state and memory identity across processes,
    // not a process-local condition or FD/Handle number.
    mode = 7;
    struct shared_state { pthread_mutex_t mutex; pthread_cond_t cond; unsigned allowed; };
    struct shared_state *mapped = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(mapped != MAP_FAILED);
    pthread_mutexattr_t mutex_attr;
    CHECK(pthread_mutexattr_init(&mutex_attr) == 0);
    CHECK(pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED) == 0);
    CHECK(pthread_condattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) == 0);
    CHECK(pthread_mutex_init(&mapped->mutex, &mutex_attr) == 0 && pthread_cond_init(&mapped->cond, &attr) == 0);
    int pipes[2];
    CHECK(pipe(pipes) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        if (pthread_mutex_lock(&mapped->mutex) || write(pipes[1], "r", 1) != 1) _exit(2);
        while (!mapped->allowed) if (pthread_cond_wait(&mapped->cond, &mapped->mutex)) _exit(3);
        if (pthread_mutex_unlock(&mapped->mutex)) _exit(4);
        _exit(0);
    }
    char byte = 0;
    CHECK(read(pipes[0], &byte, 1) == 1 && byte == 'r');
    CHECK(pthread_mutex_lock(&mapped->mutex) == 0);
    mapped->allowed = 1;
    CHECK(pthread_cond_signal(&mapped->cond) == 0 && pthread_mutex_unlock(&mapped->mutex) == 0);
    int status = -1;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(pthread_cond_destroy(&mapped->cond) == 0 && pthread_mutex_destroy(&mapped->mutex) == 0);
    CHECK(munmap(mapped, 4096) == 0 && close(pipes[0]) == 0 && close(pipes[1]) == 0);
    CHECK(pthread_mutexattr_destroy(&mutex_attr) == 0);
    CHECK(pthread_cond_destroy(&cond) == 0);
    CHECK(pthread_condattr_destroy(&attr) == 0);
    CHECK(pthread_condattr_getclock(&attr, &clock) == EINVAL);
    CHECK(pthread_mutex_destroy(&mutex) == 0);
    debug("native-pthread-cond: PASS signal/broadcast, clocks, cancellation reacquisition, signal replacement, handler restart and process sharing\n");
    return 0;
}
