/* Run real callback dispatch and allocator/registration contention in one
 * isolated process, including the registry inherited by subsequent forks. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
#undef CHECK
#define main fork_reent_probe
#include "native_fork_reent.c"
#undef main
#undef CHECK
#define main resource_policy_probe
#include "native_resource_policy.c"
#undef main
#undef CHECK
#define main file_size_limit_probe
#include "native_file_size_limit.c"
#undef main
#undef CHECK
#define main bounded_write_probe
#include "native_bounded_write.c"
#undef main
#undef CHECK
#define main program_break_probe
#include "native_program_break.c"
#undef main
#undef CHECK
#define main mapping_budget_probe
#include "native_mapping_budget.c"
#undef main
#undef CHECK
#define main address_space_limit_probe
#include "native_address_space_limit.c"
#undef main
#undef CHECK
#define main heap_reservation_probe
#include "native_heap_reservation.c"
#undef main
#undef CHECK
#define main image_limit_probe
#include "native_exec_address_space.c"
#undef main
#undef CHECK
#define main child_startup_probe
#include "native_child_startup.c"
#undef main
#undef CHECK
#define main shm_size_limit_probe
#include "native_shared_memory_size_limit.c"
#undef main
#undef CHECK
#define main shm_write_limit_probe
#include "native_shared_memory_write_limit.c"
#undef main
#undef CHECK
#define main process_limit_probe
#include "native_process_limit.c"
#undef main
#undef CHECK
#define main fd_lease_probe
#include "native_fd_lease.c"
#undef main

int main(int argc, char **argv) {
    int mode = image_limit_child(argc, argv);
    if (mode >= 0) return mode;
    int result = handle_capture_probe();
    if (result) return result;
    result = snapshot_probe();
    if (result) return result;
    result = barrier_probe();
    if (result) return result;
    result = newlib_lock_probe();
    if (result) return result;
    result = fork_capture_probe();
    if (result) return result;
    result = fork_reent_probe();
    if (result) return result;
    result = resource_policy_probe();
    if (result) return result;
    result = file_size_limit_probe();
    if (result) return result;
    result = shm_size_limit_probe();
    if (result) return result;
    result = shm_write_limit_probe();
    if (result) return result;
    result = bounded_write_probe();
    if (result) return result;
    result = program_break_probe();
    if (result) return result;
    result = mapping_budget_probe();
    if (result) return result;
    result = heap_reservation_probe();
    if (result) return result;
    result = address_space_limit_probe();
    if (result) return result;
    result = image_limit_probe(0, NULL);
    if (result) return result;
    result = child_startup_probe();
    if (result) return result;
    result = process_limit_probe();
    if (result) return result;
    result = fd_lease_probe();
    return result ? result : callback_probe();
}
