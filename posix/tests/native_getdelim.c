#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static unsigned mode;
static FILE *stream;
static char *line;
static size_t capacity;
static _Atomic unsigned ready, cleaned;

static void debug(const char *message) {
    uint64_t number = 660;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"((uintptr_t)message), "S"((uint64_t)strlen(message))
                     : "rcx", "r11", "memory");
}

#define CHECK(condition) do { if (!(condition)) { \
    char message[128]; \
    snprintf(message, sizeof(message), "native-getdelim: FAIL mode=%u line=%u errno=%d\n", mode, __LINE__, errno); \
    debug(message); return 1; \
} } while (0)

static void cleanup(void *unused) {
    (void)unused;
    free(line);
    line = NULL;
    atomic_store(&cleaned, 1);
}

static void *reader(void *unused) {
    (void)unused;
    pthread_cleanup_push(cleanup, NULL);
    atomic_store(&ready, 1);
    if (mode == 0) getline(&line, &capacity, stream);
    else getdelim(&line, &capacity, '|', stream);
    pthread_cleanup_pop(0);
    return (void *)1;
}

static int await_flag(_Atomic unsigned *flag) {
    for (unsigned retry = 0; retry < 2000; ++retry) {
        if (atomic_load(flag)) return 1;
        struct timespec delay = {0, 1000000};
        if (nanosleep(&delay, NULL) != 0) return 0;
    }
    return 0;
}

int main(void) {
    int pipes[2];
    CHECK(pipe(pipes) == 0);
    unsigned char input[608];
    memset(input, 'x', 599);
    input[599] = '\n';
    memcpy(input + 600, "a\0b|tail", 8);
    CHECK(write(pipes[1], input, sizeof(input)) == (ssize_t)sizeof(input));
    CHECK(close(pipes[1]) == 0);
    stream = fdopen(pipes[0], "r");
    CHECK(stream != NULL);
    CHECK(getline(&line, &capacity, stream) == 600 && capacity >= 601);
    CHECK(memcmp(line, input, 600) == 0 && line[600] == 0);
    CHECK(getdelim(&line, &capacity, '|', stream) == 4);
    CHECK(memcmp(line, input + 600, 4) == 0 && line[4] == 0);
    CHECK(getline(&line, &capacity, stream) == 4 && strcmp(line, "tail") == 0);
    errno = 123;
    CHECK(getline(&line, &capacity, stream) == -1 && feof(stream) && !ferror(stream) && errno == 123);
    clearerr(stream);
    errno = 0;
    CHECK(getline(NULL, &capacity, stream) == -1 && errno == EINVAL && ferror(stream));
    CHECK(fclose(stream) == 0);
    free(line);
    line = NULL;
    capacity = 0;
    for (mode = 0; mode < 2; ++mode) {
        atomic_store(&ready, 0);
        atomic_store(&cleaned, 0);
        CHECK(pipe(pipes) == 0);
        stream = fdopen(pipes[0], "r");
        CHECK(stream != NULL);
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, reader, NULL) == 0);
        CHECK(await_flag(&ready));
        struct timespec delay = {0, 20000000};
        CHECK(nanosleep(&delay, NULL) == 0);
        CHECK(pthread_cancel(thread) == 0);
        CHECK(await_flag(&cleaned)); // No external I/O releases the read.
        void *result = NULL;
        CHECK(pthread_join(thread, &result) == 0 && result == PTHREAD_CANCELED && line == NULL);
        CHECK(ftrylockfile(stream) == 0);
        funlockfile(stream);
        CHECK(fclose(stream) == 0 && close(pipes[1]) == 0);
        capacity = 0;
    }
    debug("native-getdelim: PASS public headers, growth, embedded NUL, EOF, errors and cancellation cleanup\n");
    return 0;
}
