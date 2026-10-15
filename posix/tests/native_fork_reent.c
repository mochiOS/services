#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <reent.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { printf("fork-reent: FAIL line=%d errno=%d\n", __LINE__, errno); return 1; } } while (0)
static FILE *fr_file;
static atomic_uint_fast64_t fr_native_handle;
static atomic_int fr_cleanup_calls, fr_cleanup_result, fr_worker_error;
static int64_t fr_native(uint64_t number, uint64_t a, uint64_t b) {
    __asm__ volatile("syscall" : "+a"(number) : "D"(a), "S"(b) : "rcx", "r11", "memory");
    return (int64_t)number;
}
static void fr_cleanup(struct _reent *unused) {
    (void)unused;
    atomic_fetch_add(&fr_cleanup_calls, 1);
    atomic_store(&fr_cleanup_result, fclose(fr_file));
}
static void *fr_worker(void *unused) {
    (void)unused;
    struct _reent *reent = __getreent();
    /* Exercise real _reclaim_reent private-cache freeing as well as a cleanup
     * callback which must run only during the parent's eventual join. */
    if (_REENT_CVTBUF(reent)) { atomic_store(&fr_worker_error, 1); return NULL; }
    _REENT_CVTBUF(reent) = malloc(32);
    if (!_REENT_CVTBUF(reent)) { atomic_store(&fr_worker_error, 2); return NULL; }
    _REENT_CLEANUP(reent) = fr_cleanup;
    int64_t handle = fr_native(656, 0, 0);
    if (handle <= 0) { atomic_store(&fr_worker_error, 3); return NULL; }
    atomic_store(&fr_native_handle, (uint64_t)handle);
    return NULL;
}
int main(void) {
    fr_file = fopen("/tmp/native-fork-reent", "w+");
    CHECK(fr_file && unlink("/tmp/native-fork-reent") == 0);
    int descriptor = fileno(fr_file);
    CHECK(descriptor >= 0);
    pthread_t worker;
    CHECK(pthread_create(&worker, NULL, fr_worker, NULL) == 0);
    uint64_t handle;
    while (!(handle = atomic_load(&fr_native_handle))) {
        CHECK(!atomic_load(&fr_worker_error));
        sched_yield();
    }
    /* Wait for native exit without joining: its TCB/reent is still retained.
     * This is a real single-live-thread fork, not relaxed pthread policy. */
    struct { uint64_t thread, process; uint32_t state, reserved; } status;
    do {
        int64_t result = fr_native(658, handle, (uint64_t)&status);
        if (result == -3) break; /* Native record already reclaimed, as in the runtime's join path. */
        CHECK(result == 0);
        if (status.state != 5) sched_yield();
    } while (status.state != 5);
    CHECK(fr_native(626, handle, 0) == 0);
    CHECK(!atomic_load(&fr_cleanup_calls));
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        if (atomic_load(&fr_cleanup_calls)) _exit(11);
        if (fcntl(descriptor, F_GETFD) < 0) _exit(12);
        if (fputs("child", fr_file) < 0 || fflush(fr_file)) _exit(13);
        _exit(0);
    }
    int child_status;
    CHECK(waitpid(child, &child_status, 0) == child && WIFEXITED(child_status));
    if (WEXITSTATUS(child_status)) printf("fork-reent: child status=%d\n", WEXITSTATUS(child_status));
    CHECK(WEXITSTATUS(child_status) == 0 && !atomic_load(&fr_cleanup_calls));
    CHECK(fcntl(descriptor, F_GETFD) >= 0);
    CHECK(pthread_join(worker, NULL) == 0);
    CHECK(atomic_load(&fr_cleanup_calls) == 1 && atomic_load(&fr_cleanup_result) == 0);
    CHECK(fcntl(descriptor, F_GETFD) == -1 && errno == EBADF);
    puts("fork-reent: PASS child discards exited sibling caches without FILE cleanup; parent join still invokes cleanup exactly once");
    return 0;
}
