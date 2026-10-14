/* Run real callback dispatch and allocator/registration contention in one
 * isolated process, including the registry inherited by subsequent forks. */
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

int main(void) {
    int result = barrier_probe();
    if (result) return result;
    result = newlib_lock_probe();
    return result ? result : callback_probe();
}
