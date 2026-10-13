#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

_Static_assert(sizeof(pthread_once_t) == 8, "newlib once ABI");
_Static_assert(offsetof(pthread_once_t, init_executed) == 4, "newlib once state");
static pthread_once_t once = PTHREAD_ONCE_INIT;
static pthread_once_t cancelled = PTHREAD_ONCE_INIT;
static pthread_once_t exited = PTHREAD_ONCE_INIT;
static pthread_once_t deferred = PTHREAD_ONCE_INIT;
static atomic_int calls, attempts, started, exit_attempts, workers_started;
static atomic_int deferred_started, release_deferred, waiter_started, waiter_returned;
static int published;
static void pause_tick(void) { struct timespec delay = {0, 1000000}; nanosleep(&delay, NULL); }
static void initialize(void) {
    atomic_fetch_add(&calls, 1);
    while (atomic_load(&workers_started) != 12) pause_tick();
    published = 42;
}
static void initialize_cancel(void) {
    if (atomic_fetch_add(&attempts, 1) == 0) {
        atomic_store(&started, 1);
        for (;;) pause_tick();
    }
}
static void initialize_exit(void) {
    if (atomic_fetch_add(&exit_attempts, 1) == 0) pthread_exit((void *)(uintptr_t)17);
}
static void initialize_deferred(void) {
    atomic_store(&deferred_started, 1);
    while (!atomic_load(&release_deferred)) pause_tick();
}
static void *deferred_owner(void *unused) { (void)unused; return (void *)(uintptr_t)pthread_once(&deferred, initialize_deferred); }
static void *deferred_waiter(void *unused) {
    (void)unused; atomic_store(&waiter_started, 1);
    if (pthread_once(&deferred, initialize_deferred)) return (void *)(uintptr_t)1;
    atomic_store(&waiter_returned, 1);
    pthread_testcancel();
    return (void *)(uintptr_t)2;
}
static void *worker(void *unused) { (void)unused; atomic_fetch_add(&workers_started, 1); return (void *)(uintptr_t)(pthread_once(&once, initialize) || published != 42); }
static void *cancel_worker(void *unused) { (void)unused; return (void *)(uintptr_t)pthread_once(&cancelled, initialize_cancel); }
static void *exit_worker(void *unused) { (void)unused; return (void *)(uintptr_t)pthread_once(&exited, initialize_exit); }
static void debug(const char *message) {
    uint64_t number = 660;
    __asm__ volatile("syscall" : "+a"(number) : "D"((uintptr_t)message), "S"((uint64_t)strlen(message)) : "rcx", "r11", "memory");
}
#define CHECK(x) do { if (!(x)) { char text[128]; snprintf(text, sizeof(text), "native-pthread-once: FAIL line=%u errno=%d\n", __LINE__, errno); debug(text); return 1; } } while (0)
int main(void) {
    pthread_t threads[12]; void *result;
    for (unsigned i = 0; i < 12; ++i) CHECK(pthread_create(&threads[i], NULL, worker, NULL) == 0);
    for (unsigned i = 0; i < 12; ++i) CHECK(pthread_join(threads[i], &result) == 0 && result == NULL);
    CHECK(atomic_load(&calls) == 1 && published == 42);
    errno = 123; CHECK(pthread_once(&once, initialize) == 0 && errno == 123);
    CHECK(pthread_create(&threads[0], NULL, cancel_worker, NULL) == 0);
    while (!atomic_load(&started)) pause_tick();
    CHECK(pthread_create(&threads[1], NULL, cancel_worker, NULL) == 0);
    CHECK(pthread_cancel(threads[0]) == 0);
    CHECK(pthread_join(threads[0], &result) == 0 && result == PTHREAD_CANCELED);
    CHECK(pthread_join(threads[1], &result) == 0 && result == NULL);
    CHECK(atomic_load(&attempts) == 2);
    CHECK(pthread_create(&threads[0], NULL, exit_worker, NULL) == 0);
    CHECK(pthread_join(threads[0], &result) == 0 && result == (void *)(uintptr_t)17);
    CHECK(pthread_once(&exited, initialize_exit) == 0 && atomic_load(&exit_attempts) == 2);
    CHECK(pthread_create(&threads[0], NULL, deferred_owner, NULL) == 0);
    while (!atomic_load(&deferred_started)) pause_tick();
    CHECK(pthread_create(&threads[1], NULL, deferred_waiter, NULL) == 0);
    while (!atomic_load(&waiter_started)) pause_tick();
    CHECK(pthread_cancel(threads[1]) == 0);
    atomic_store(&release_deferred, 1);
    CHECK(pthread_join(threads[0], &result) == 0 && result == NULL);
    CHECK(pthread_join(threads[1], &result) == 0 && result == PTHREAD_CANCELED);
    CHECK(atomic_load(&waiter_returned) == 1);
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) _exit(pthread_once(&once, initialize) || published != 42 || atomic_load(&calls) != 1);
    int status; CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    debug("native-pthread-once: PASS contention, publication, cancellation retry, pthread_exit reset, non-cancellable wait and inherited completion\n");
    return 0;
}
