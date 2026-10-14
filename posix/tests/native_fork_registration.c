/* Run real callback dispatch and allocator/registration contention in one
 * isolated process, including the registry inherited by subsequent forks. */
#define main handle_capture_probe
#include "native_handle_capture.c"
#undef main
#undef CHECK
#define main snapshot_probe
#include "native_multithread_snapshot.c"
#undef main
#undef CHECK
#define main barrier_probe
#include "native_pthread_barrier.c"
#undef main
#undef CHECK
#define main newlib_lock_probe
#include "native_newlib_fork_locks.c"
#undef main
#undef CHECK
#define main callback_probe
#include "native_atfork.c"
#undef main
#undef CHECK
#define main fork_capture_probe
#include "native_fork_capture.c"
#undef main

int main(void) {
    int result = handle_capture_probe();
    if (result) return result;
    result = snapshot_probe();
    if (result) return result;
    result = barrier_probe();
    if (result) return result;
    result = newlib_lock_probe();
    if (result) return result;
    result = fork_capture_probe();
    return result ? result : callback_probe();
}
