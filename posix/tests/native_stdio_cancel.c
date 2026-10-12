#define _GNU_SOURCE 1
/* Isolated Compositor-slot regression. A cancellation point must not require
 * external I/O to complete, and must not leave a FILE lock owned by a corpse. */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static unsigned mode;
static FILE *stream;
static _Atomic unsigned ready, cleaned, returned;
static _Atomic size_t written;

static void debug(const char *message) {
    uint64_t number = 660;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"((uintptr_t)message), "S"((uint64_t)strlen(message))
                     : "rcx", "r11", "memory");
}

#define CHECK(condition) do { if (!(condition)) { \
    char message[128]; \
    snprintf(message, sizeof(message), "native-stdio-cancel: FAIL mode=%u line=%u errno=%d\n", mode, __LINE__, errno); \
    debug(message); return 1; \
} } while (0)

static void cleanup(void *unused) {
    (void)unused;
    atomic_store(&cleaned, 1);
}

static void *worker(void *unused) {
    (void)unused;
    char buffer[32] = {0};
    char output[1024];
    memset(output, 'p', sizeof(output));
    if (mode == 4 && pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) != 0) return (void *)1;
    size_t count = 0;
    pthread_cleanup_push(cleanup, NULL);
    atomic_store(&ready, 1);
    if (mode == 0 || mode == 4) count = fread(buffer, 1, 1, stream);
    else if (mode == 1) fgetc(stream);
    else if (mode == 2) fgets(buffer, sizeof(buffer), stream);
    else count = fwrite(output, 1, mode == 5 ? sizeof(output) : 1, stream);
    atomic_store(&written, count);
    atomic_store(&returned, 1);
    if (mode == 4) pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_testcancel(); // Distinguish action inside stdio from after fallback I/O.
    pthread_cleanup_pop(0);
    return NULL;
}

static int wait_briefly(void) {
    struct timespec delay = {0, 1000000};
    return nanosleep(&delay, NULL) == 0;
}

int main(void) {
    unsigned needed_external_io = 0;
    for (mode = 0; mode < 6; ++mode) {
        int pipes[2];
        CHECK(pipe(pipes) == 0);
        if (mode == 3 || mode == 5) {
            CHECK(fcntl(pipes[1], F_SETFL, O_NONBLOCK) == 0);
            char block[512];
            memset(block, 'f', sizeof(block));
            for (;;) {
                ssize_t count = write(pipes[1], block, sizeof(block));
                if (count == -1) { CHECK(errno == EAGAIN); break; }
                CHECK(count == (ssize_t)sizeof(block));
            }
            CHECK(fcntl(pipes[1], F_SETFL, 0) == 0);
            if (mode == 5) CHECK(read(pipes[0], block, sizeof(block)) == (ssize_t)sizeof(block));
        }
        unsigned writing = mode == 3 || mode == 5;
        stream = fdopen(pipes[writing ? 1 : 0], writing ? "w" : "r");
        CHECK(stream != NULL && setvbuf(stream, NULL, _IONBF, 0) == 0);
        atomic_store(&ready, 0);
        atomic_store(&cleaned, 0);
        atomic_store(&returned, 0);
        atomic_store(&written, 0);
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, worker, NULL) == 0);
        for (unsigned retry = 0; retry < 2000 && !atomic_load(&ready); ++retry) CHECK(wait_briefly());
        CHECK(atomic_load(&ready) == 1);
        struct timespec delay = {0, 20000000};
        CHECK(nanosleep(&delay, NULL) == 0);
        CHECK(pthread_cancel(thread) == 0);
        if (mode == 4) {
            CHECK(nanosleep(&delay, NULL) == 0 && atomic_load(&cleaned) == 0);
            CHECK(write(pipes[1], "d", 1) == 1);
        }
        for (unsigned retry = 0; retry < 500 && !atomic_load(&cleaned); ++retry) CHECK(wait_briefly());
        if (!atomic_load(&cleaned)) {
            ++needed_external_io;
            char message[128];
            snprintf(message, sizeof(message), "native-stdio-cancel: blocked mode=%u requires fallback I/O after cancellation\n", mode);
            debug(message);
            // Bound the regression test: release I/O instead of leaving a
            // permanently blocked worker. This does not count as test success.
            if (writing) {
                char block[512];
                CHECK(read(pipes[0], block, sizeof(block)) == (ssize_t)sizeof(block));
            } else CHECK(write(pipes[1], "v\n", 2) == 2);
        }
        void *result = NULL;
        CHECK(pthread_join(thread, &result) == 0 && result == PTHREAD_CANCELED);
        CHECK(atomic_load(&cleaned) == 1);
        CHECK(atomic_load(&returned) == (mode >= 4 ? 1u : 0u));
        if (mode >= 4) CHECK(atomic_load(&written) == (mode == 4 ? 1u : 512u));
        // Check from another thread, not from the cancelled owner: recursive
        // ftrylockfile by the old owner would falsely hide a stranded lock.
        CHECK(ftrylockfile(stream) == 0);
        funlockfile(stream);
        CHECK(fclose(stream) == 0);
        CHECK(close(pipes[writing ? 0 : 1]) == 0);
    }
    CHECK(needed_external_io == 0);
    debug("native-stdio-cancel: PASS blocked stdio, released FILE locks, disabled cancellation and partial progress\n");
    return 0;
}
