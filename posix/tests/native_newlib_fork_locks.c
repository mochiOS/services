#include <pthread.h>
#include <errno.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
#ifdef __mochios__
#include <sys/lock.h>
static _LOCK_RECURSIVE_T lock;
extern struct __lock __lock___malloc_recursive_mutex;
static _LOCK_RECURSIVE_T allocator_lock = &__lock___malloc_recursive_mutex;
#endif

#define CHECK(x) do { if (!(x)) { printf("newlib-fork-locks: FAIL line=%d\n", __LINE__); return 1; } } while (0)

#ifdef __mochios__
static atomic_int arena_ready, fork_entered, arena_stop;
static atomic_int registration_error;
static atomic_int policy_error;
static void *arena_writer(void *unused) {
    (void)unused;
    __lock_acquire_recursive(allocator_lock);
    atomic_store(&arena_ready, 1);
    while (!atomic_load(&fork_entered)) sched_yield();
    struct timespec delay = { .tv_nsec = 100000000 };
    while (nanosleep(&delay, &delay) && errno == EINTR) {}
    /* Fork must not hold POLICY while waiting for this allocator lock.
     * This is also the lock order needed by future sbrk limit checks. */
    struct rlimit limit;
    atomic_store(&policy_error, getrlimit(RLIMIT_DATA, &limit));
    /* Fork must not hold REGISTRY while waiting for this allocator lock. */
    atomic_store(&registration_error, pthread_atfork(NULL, NULL, NULL));
    __lock_release_recursive(allocator_lock);
    /* Stay live so the runtime still rejects a multithreaded source. */
    while (!atomic_load(&arena_stop)) sched_yield();
    return NULL;
}
static int serialized_arena(void) {
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, arena_writer, NULL) == 0);
    while (!atomic_load(&arena_ready)) sched_yield();
    atomic_store(&fork_entered, 1);
    pid_t child = fork();
    int error = errno;
    if (child == 0) _exit(48);
    atomic_store(&arena_stop, 1);
    void *result;
    CHECK(pthread_join(thread, &result) == 0 && result == NULL);
    CHECK(child == -1 && error == EAGAIN
        && !atomic_load(&registration_error) && !atomic_load(&policy_error));
    puts("newlib-fork-locks: PASS clone rejects foreign libc mutation without copying partial state");
    puts("newlib-fork-locks: PASS atfork registration under allocator ownership does not invert clone locks");
    puts("newlib-fork-locks: PASS resource policy reads under allocator ownership do not invert fork locks");
    return 0;
}
#endif

static void *contender(void *unused) {
    (void)unused;
#ifdef __mochios__
    if (__lock_try_acquire_recursive(lock)) {
        __lock_release_recursive(lock);
        return (void *)(uintptr_t)1;
    }
#endif
    if (ftrylockfile(stdout) == 0) {
        funlockfile(stdout);
        return (void *)(uintptr_t)2;
    }
    return NULL;
}

static int retained_ownership(void) {
#ifdef __mochios__
    if (!__lock_try_acquire_recursive(lock)) return 41;
    __lock_release_recursive(lock);
    if (!__lock_try_acquire_recursive(allocator_lock)) return 46;
    void *memory = malloc(32);
    if (!memory) return 47;
    free(memory);
    __lock_release_recursive(allocator_lock);
#endif
    if (ftrylockfile(stdout)) return 42;
    funlockfile(stdout);
    return 0;
}

static void release_locks(void) {
#ifdef __mochios__
    __lock_release_recursive(allocator_lock);
    __lock_release_recursive(allocator_lock);
    __lock_release_recursive(lock);
    __lock_release_recursive(lock);
    __lock_close_recursive(lock);
#endif
    funlockfile(stdout);
    funlockfile(stdout);
}

static int fork_locked(unsigned nested) {
    pid_t child = fork();
    if (child < 0) return 43;
    if (child == 0) {
        int result = retained_ownership();
        if (!result && nested) result = fork_locked(nested - 1);
        if (result) _exit(result);
        release_locks();
        void *memory = malloc(4096);
        if (!memory) _exit(44);
        free(memory);
        /* The inherited FILE lock must also support blocking acquisition. */
        flockfile(stdout);
        funlockfile(stdout);
        _exit(0);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return 45;
    return WEXITSTATUS(status);
}

int main(void) {
#ifdef __mochios__
    CHECK(serialized_arena() == 0);
    __lock_init_recursive(lock);
    __lock_acquire_recursive(lock);
    __lock_acquire_recursive(lock);
#endif
    flockfile(stdout);
    flockfile(stdout);
    /* Neither another thread nor a reused thread slot may impersonate us. */
    for (unsigned i = 0; i < 2; ++i) {
        pthread_t thread;
        void *result;
        CHECK(pthread_create(&thread, NULL, contender, NULL) == 0);
        CHECK(pthread_join(thread, &result) == 0 && result == NULL);
    }
#ifdef __mochios__
    /* Acquire after joins: a terminating contender may free its reent. */
    __lock_acquire_recursive(allocator_lock);
    __lock_acquire_recursive(allocator_lock);
#endif
    int result = fork_locked(1);
    if (result) printf("newlib-fork-locks: child failure=%d\n", result);
    CHECK(result == 0);
    CHECK(retained_ownership() == 0);
    release_locks();
    puts("newlib-fork-locks: PASS recursive private locks and FILE ownership survive nested fork without admitting other threads");
    return 0;
}
