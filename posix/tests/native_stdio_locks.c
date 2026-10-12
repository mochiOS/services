#define _GNU_SOURCE 1
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static FILE *stream;
static _Atomic unsigned tried, done;
static _Atomic int try_result;

static void debug(const char *message) {
    uint64_t number = 660;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"((uintptr_t)message), "S"((uint64_t)strlen(message))
                     : "rcx", "r11", "memory");
}

#define CHECK(condition) do { if (!(condition)) { \
    char message[128]; \
    snprintf(message, sizeof(message), "native-stdio-locks: FAIL line=%u errno=%d\n", __LINE__, errno); \
    debug(message); return 1; \
} } while (0)

static void *reader(void *unused) {
    (void)unused;
    errno = 123;
    int result = ftrylockfile(stream);
    atomic_store(&try_result, result);
    if (result == 0) funlockfile(stream);
    if (errno != 123) return (void *)1;
    atomic_store(&tried, 1);
    int byte = fgetc(stream); // Same lock as public flockfile, despite readable FD.
    atomic_store(&done, 1);
    return byte == 'q' ? NULL : (void *)2;
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
    stream = fdopen(pipes[0], "r");
    CHECK(stream != NULL && setvbuf(stream, NULL, _IONBF, 0) == 0);
    CHECK(write(pipes[1], "q", 1) == 1);
    errno = 123;
    flockfile(stream);
    flockfile(stream);
    CHECK(ftrylockfile(stream) == 0 && errno == 123);
    funlockfile(stream); // Still recursively held twice.
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, reader, NULL) == 0);
    CHECK(await_flag(&tried));
    CHECK(atomic_load(&try_result) != 0);
    struct timespec delay = {0, 20000000};
    CHECK(nanosleep(&delay, NULL) == 0 && atomic_load(&done) == 0);
    funlockfile(stream);
    CHECK(nanosleep(&delay, NULL) == 0 && atomic_load(&done) == 0);
    funlockfile(stream);
    CHECK(await_flag(&done));
    void *result = NULL;
    CHECK(pthread_join(thread, &result) == 0 && result == NULL);
    CHECK(ftrylockfile(stream) == 0);
    funlockfile(stream);
    CHECK(fclose(stream) == 0 && close(pipes[1]) == 0);
    debug("native-stdio-locks: PASS recursion, busy return, errno and shared internal FILE lock\n");
    return 0;
}
