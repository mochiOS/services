/* Generic VM capture with executing and blocked native sibling contexts.
 * No POSIX child/FD inheritance is requested by these detached images. */
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static atomic_uint_fast64_t snapshot_writes;
static atomic_int snapshot_stop, snapshot_reader_ready, snapshot_reader_result;
static int snapshot_channel[2];
static void *snapshot_writer(void *unused) {
    (void)unused;
    while (!atomic_load(&snapshot_stop)) atomic_fetch_add(&snapshot_writes, 1);
    return NULL;
}
static void *snapshot_reader(void *unused) {
    (void)unused;
    atomic_store(&snapshot_reader_ready, 1);
    char marker;
    atomic_store(&snapshot_reader_result,
        read(snapshot_channel[0], &marker, 1) == 1 && marker == 'x' ? 1 : -1);
    return NULL;
}
static int64_t snapshot_native(uint64_t number, uint64_t argument) {
    __asm__ volatile("syscall" : "+a"(number) : "D"(argument)
        : "rcx", "r11", "memory");
    return (int64_t)number;
}
#define CHECK(x) do { if (!(x)) { printf("native-image-quiescence: FAIL line=%d\n", __LINE__); return 1; } } while (0)
int main(void) {
    pthread_t writer, reader;
    CHECK(pipe(snapshot_channel) == 0);
    CHECK(pthread_create(&writer, NULL, snapshot_writer, NULL) == 0);
    CHECK(pthread_create(&reader, NULL, snapshot_reader, NULL) == 0);
    while (!atomic_load(&snapshot_reader_ready) || atomic_load(&snapshot_writes) < 1000) sched_yield();
    for (unsigned attempt = 0; attempt < 12; ++attempt) {
        int64_t image = snapshot_native(679 /* AddressSpaceClone */, 0);
        CHECK(image > 0);
        /* Keep the image alive while the source writes: exercise source COW
         * faults as well as resumption of the temporarily held thread. */
        uint64_t after = atomic_load(&snapshot_writes);
        while (atomic_load(&snapshot_writes) == after) sched_yield();
        CHECK(snapshot_native(626 /* HandleClose */, (uint64_t)image) == 0);
        CHECK(atomic_load(&snapshot_reader_result) == 0);
    }
    CHECK(write(snapshot_channel[1], "x", 1) == 1);
    atomic_store(&snapshot_stop, 1);
    void *result;
    CHECK(pthread_join(writer, &result) == 0 && result == NULL);
    CHECK(pthread_join(reader, &result) == 0 && result == NULL);
    CHECK(atomic_load(&snapshot_reader_result) == 1);
    CHECK(close(snapshot_channel[0]) == 0 && close(snapshot_channel[1]) == 0);
    puts("native-image-quiescence: PASS repeated VM capture with running/blocked siblings, source COW writes and restored wakeups");
    return 0;
}
