#define _GNU_SOURCE 1
/* Isolated Compositor-slot probe of public C pipe I/O cancellation points. */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

static int pipes[2];
static unsigned mode;
static _Atomic unsigned ready, release_entry, cleanup_ran, returned;
static _Atomic size_t progress;
static unsigned char read_buffer[32];

static void debug(const char *message) {
    uint64_t number = 660;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"((uintptr_t)message), "S"((uint64_t)strlen(message))
                     : "rcx", "r11", "memory");
}

#define CHECK(condition) do { if (!(condition)) { \
    char message[128]; \
    snprintf(message, sizeof(message), "native-stream-cancel: FAIL mode=%u line=%u errno=%d\n", mode, __LINE__, errno); \
    debug(message); return 1; \
} } while (0)

static int await_flag(_Atomic unsigned *flag) {
    for (unsigned retry = 0; retry < 2000; ++retry) {
        if (atomic_load(flag)) return 1;
        struct timespec delay = {0, 1000000};
        if (nanosleep(&delay, NULL) != 0) return 0;
    }
    return 0;
}

static void cleanup(void *unused) {
    (void)unused;
    atomic_store(&cleanup_ran, 1);
}

static void *worker(void *unused) {
    (void)unused;
    char output[1024];
    memset(output, 'p', sizeof(output));
    struct iovec input_vectors[2] = {{read_buffer, 16}, {read_buffer + 16, 16}};
    struct iovec output_vectors[2] = {{output, 1}, {output + 1, 1}};
    if (mode == 5 && pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) != 0) return (void *)1;
    ssize_t result = -1;
    pthread_cleanup_push(cleanup, NULL);
    atomic_store(&ready, 1);
    if (mode >= 6) while (!atomic_load(&release_entry)) sched_yield();
    switch (mode) {
        case 0: case 5: result = read(pipes[0], read_buffer, 1); break;
        case 1: result = write(pipes[1], output, 1); break;
        case 2: result = readv(pipes[0], input_vectors, 2); break;
        case 3: result = writev(pipes[1], output_vectors, 2); break;
        case 4: result = write(pipes[1], output, sizeof(output)); break;
        case 6: result = read(pipes[0], NULL, 0); break;
        case 7: result = write(pipes[1], NULL, 0); break;
    }
    if ((mode == 4 && result == 512) || (mode == 5 && result == 1)) {
        atomic_store(&progress, (size_t)result);
        atomic_store(&returned, 1);
        if (mode == 5) pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        pthread_testcancel(); // A partial success left the request pending.
    } else atomic_store(&returned, 2);
    pthread_cleanup_pop(0);
    return (void *)(intptr_t)result;
}

int main(void) {
    for (mode = 0; mode < 8; ++mode) {
        atomic_store(&ready, 0);
        atomic_store(&release_entry, 0);
        atomic_store(&cleanup_ran, 0);
        atomic_store(&returned, 0);
        atomic_store(&progress, 0);
        memset(read_buffer, 0x22, sizeof(read_buffer));
        CHECK(pipe(pipes) == 0);
        size_t filled = 0;
        char block[512];
        memset(block, 'f', sizeof(block));
        if (mode == 1 || mode == 3 || mode == 4) {
            CHECK(fcntl(pipes[1], F_SETFL, O_NONBLOCK) == 0);
            for (;;) {
                ssize_t count = write(pipes[1], block, sizeof(block));
                if (count == -1) { CHECK(errno == EAGAIN); break; }
                CHECK(count == (ssize_t)sizeof(block));
                filled += (size_t)count;
                CHECK(filled <= 1024 * 1024);
            }
            CHECK(fcntl(pipes[1], F_SETFL, 0) == 0);
            if (mode == 4) CHECK(read(pipes[0], block, sizeof(block)) == (ssize_t)sizeof(block));
        }
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, worker, NULL) == 0);
        CHECK(await_flag(&ready));
        struct timespec delay = {0, 20000000};
        if (mode < 6) CHECK(nanosleep(&delay, NULL) == 0);
        CHECK(pthread_cancel(thread) == 0);
        atomic_store(&release_entry, 1);
        if (mode == 5) {
            CHECK(nanosleep(&delay, NULL) == 0 && atomic_load(&returned) == 0);
            CHECK(write(pipes[1], "x", 1) == 1);
        }
        CHECK(await_flag(&cleanup_ran));
        void *result = NULL;
        CHECK(pthread_join(thread, &result) == 0 && result == PTHREAD_CANCELED);
        CHECK(atomic_load(&returned) == (mode == 4 || mode == 5 ? 1u : 0u));
        if (mode == 0 || mode == 2) {
            for (size_t index = 0; index < sizeof(read_buffer); ++index) CHECK(read_buffer[index] == 0x22);
        }
        if (filled != 0) {
            CHECK(fcntl(pipes[0], F_SETFL, O_NONBLOCK) == 0);
            size_t drained = 0;
            for (;;) {
                ssize_t count = read(pipes[0], block, sizeof(block));
                if (count == -1) { CHECK(errno == EAGAIN); break; }
                CHECK(count > 0);
                for (ssize_t index = 0; index < count; ++index) {
                    char expected = mode == 4 && drained + (size_t)index >= filled - 512 ? 'p' : 'f';
                    CHECK(block[index] == expected);
                }
                drained += (size_t)count;
            }
            CHECK(drained == filled);
            if (mode == 4) CHECK(atomic_load(&progress) == 512);
        }
        CHECK(close(pipes[0]) == 0 && close(pipes[1]) == 0);
    }
    debug("native-stream-cancel: PASS scalar/vector waits, partial progress, zero I/O and disabled cancellation\n");
    return 0;
}
