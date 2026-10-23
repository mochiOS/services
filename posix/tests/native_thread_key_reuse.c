/* Run on mochiOS. Exhaust the public key table, then race deletion/reuse of
 * its only available slot and execute the newly installed destructor. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "thread-key-reuse: FAIL line=%d\n", __LINE__); \
        return 1; \
    } \
} while (0)

static pthread_key_t held[4096];
static _Atomic unsigned destructors;
struct cycle {
    pthread_key_t retiring, replacement;
    pthread_barrier_t start;
    _Atomic int ready;
};
static void destroy(void *value) {
    if ((uintptr_t)value != 17)
        _exit(91);
    atomic_fetch_add(&destructors, 1);
}
static void *retire(void *argument) {
    struct cycle *cycle = argument;
    int barrier = pthread_barrier_wait(&cycle->start);
    if ((barrier != 0 && barrier != PTHREAD_BARRIER_SERIAL_THREAD) ||
        pthread_key_delete(cycle->retiring))
        _exit(92);
    while (!atomic_load_explicit(&cycle->ready, memory_order_acquire))
        sched_yield();
    if (pthread_setspecific(cycle->replacement, (void *)(uintptr_t)17))
        _exit(93);
    return NULL;
}
int main(void) {
    unsigned used = 0;
    for (; used < 4096; ++used) {
        int error = pthread_key_create(&held[used], NULL);
        if (error) {
            CHECK(error == EAGAIN);
            break;
        }
    }
    CHECK(used > 0 && used < 4096);
    pthread_key_t current = held[--used];
    for (unsigned iteration = 0; iteration < 128; ++iteration) {
        struct cycle cycle = {.retiring = current};
        pthread_t thread;
        CHECK(pthread_barrier_init(&cycle.start, NULL, 2) == 0);
        CHECK(pthread_create(&thread, NULL, retire, &cycle) == 0);
        int barrier = pthread_barrier_wait(&cycle.start);
        CHECK(barrier == 0 || barrier == PTHREAD_BARRIER_SERIAL_THREAD);
        unsigned retries = 0;
        int error;
        while ((error = pthread_key_create(&cycle.replacement, destroy)) == EAGAIN) {
            if (++retries == 1000000)
                _exit(94);
            sched_yield();
        }
        CHECK(error == 0);
        atomic_store_explicit(&cycle.ready, 1, memory_order_release);
        CHECK(pthread_join(thread, NULL) == 0);
        CHECK(atomic_load(&destructors) == iteration + 1);
        CHECK(pthread_barrier_destroy(&cycle.start) == 0);
        current = cycle.replacement;
    }
    CHECK(pthread_key_delete(current) == 0);
    for (unsigned index = 0; index < used; ++index)
        CHECK(pthread_key_delete(held[index]) == 0);
    fprintf(stderr, "thread-key-reuse: pass\n");
    return 0;
}
