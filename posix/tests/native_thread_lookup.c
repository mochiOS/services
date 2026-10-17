/* Run in the isolated Compositor role with its existing fork authority.
 * Exercise private lock identity after nested fork and under sibling activity,
 * then measure allocator and file I/O costs with the exact same runtime. */
#define main native_newlib_fork_locks_main
#include "native_newlib_fork_locks.c"
#undef main
#define main native_dictionary_read_main
#include "native_dictionary_read.c"
#undef main

int main(void) {
    int result = native_newlib_fork_locks_main();
    if (result != 0)
        return result;
    return native_dictionary_read_main();
}
