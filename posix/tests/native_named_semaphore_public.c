#include <semaphore.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <stdatomic.h>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *name = "/native-semaphore-public";
static sem_t *expected;
static atomic_int signal_waiting;
static volatile sig_atomic_t handler_posts, handler_error;
struct handle_info { uint32_t handle, reserved; uint64_t rights; };
static uint64_t call(uint64_t number, uint64_t a, uint64_t b) {
    __asm__ volatile("syscall" : "+a"(number) : "D"(a), "S"(b) : "rcx", "r11", "memory");
    return number;
}
static int memory_object_count(void) {
    struct handle_info handles[256];
    int64_t count = (int64_t)call(680, (uintptr_t)handles, 256);
    if (count < 0 || count > 256) return -1;
    int objects = 0;
    for (int64_t i = 0; i < count; ++i) {
        if ((int64_t)call(672, handles[i].handle, 0) >= 0) ++objects;
    }
    return objects;
}
static void on_signal(int number) {
    int saved = errno;
    if (number == SIGUSR1) {
        if (sem_post(expected)) handler_error = 1;
        ++handler_posts;
    }
    errno = saved;
}
static void *signal_waiter(void *unused) {
    (void)unused;
    errno = 123;
    atomic_store(&signal_waiting, 1);
    int result = sem_wait(expected);
    if (result == 0) return (void *)(uintptr_t)(errno == 123 ? 0 : 999);
    return (void *)(uintptr_t)errno;
}
static void debug(const char *text) {
    uint64_t number = 660;
    __asm__ volatile("syscall" : "+a"(number) : "D"((uintptr_t)text), "S"((uint64_t)strlen(text)) : "rcx", "r11", "memory");
}
#define CHECK(x) do { if (!(x)) { char text[128]; snprintf(text, sizeof(text), "native-named-semaphore-public: FAIL line=%u errno=%d\n", __LINE__, errno); debug(text); return 1; } } while (0)
static void *opener(void *unused) {
    (void)unused;
    sem_t *semaphore = sem_open(name, 0);
    if (semaphore == SEM_FAILED || semaphore != expected) return (void *)(uintptr_t)1;
    if (sem_post(semaphore) || sem_close(semaphore)) return (void *)(uintptr_t)2;
    return NULL;
}
int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--exec-semaphore-child") == 0) {
        CHECK(memory_object_count() == 0);
        sem_t *old = (sem_t *)(uintptr_t)strtoull(argv[2], NULL, 16);
        CHECK(sem_close(old) == -1 && errno == EINVAL);
        sem_t *reopened = sem_open(name, 0);
        CHECK(reopened != SEM_FAILED && sem_post(reopened) == 0 && sem_close(reopened) == 0);
        CHECK(memory_object_count() == 0);
        debug("native-named-semaphore-public: exec dropped old backing Handles and local mapping references\n");
        return 0;
    }
    errno = 123;
    sem_t *first = sem_open(name, O_CREAT | O_EXCL, (mode_t)0600, 3u);
    CHECK(first != SEM_FAILED && errno == 123);
    sem_t *second = sem_open(name, 0); // No variadic arguments.
    CHECK(second == first && errno == 123);
    CHECK(sem_open(name, O_CREAT | O_EXCL, (mode_t)0600, 0u) == SEM_FAILED && errno == EEXIST);
    CHECK(sem_close(first) == 0);
    int value; CHECK(sem_getvalue(second, &value) == 0 && value == 3);
    CHECK(sem_unlink(name) == 0);
    CHECK(sem_open(name, 0) == SEM_FAILED && errno == ENOENT);
    sem_t *fresh = sem_open(name, O_CREAT | O_EXCL, (mode_t)0600, 0u);
    CHECK(fresh != SEM_FAILED && fresh != second);
    CHECK(sem_getvalue(fresh, &value) == 0 && value == 0);
    CHECK(sem_trywait(second) == 0 && sem_getvalue(second, &value) == 0 && value == 2);
    CHECK(sem_close(second) == 0);
    CHECK(sem_close(second) == -1 && errno == EINVAL);
    debug("native-named-semaphore-public: repeated open, unlink and recreation passed\n");

    expected = fresh;
    pthread_t threads[8]; void *result;
    for (int i = 0; i < 8; ++i) CHECK(pthread_create(&threads[i], NULL, opener, NULL) == 0);
    for (int i = 0; i < 8; ++i) CHECK(pthread_join(threads[i], &result) == 0 && result == NULL);
    CHECK(sem_getvalue(fresh, &value) == 0 && value == 8);
    for (int i = 0; i < 8; ++i) CHECK(sem_trywait(fresh) == 0);
    struct sigaction previous, action = {0};
    action.sa_handler = on_signal; CHECK(sigemptyset(&action.sa_mask) == 0);
    CHECK(sigaction(SIGUSR1, &action, &previous) == 0);
    for (int restart = 0; restart <= 1; ++restart) {
        action.sa_flags = restart ? SA_RESTART : 0;
        CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
        handler_posts = 0; handler_error = 0; atomic_store(&signal_waiting, 0);
        CHECK(pthread_create(&threads[0], NULL, signal_waiter, NULL) == 0);
        struct timespec delay = {0, 10000000};
        while (!atomic_load(&signal_waiting)) CHECK(nanosleep(&delay, NULL) == 0);
        CHECK(nanosleep(&delay, NULL) == 0);
        CHECK(pthread_kill(threads[0], SIGUSR1) == 0);
        CHECK(pthread_join(threads[0], &result) == 0);
        CHECK(handler_posts == 1 && handler_error == 0);
        CHECK((uintptr_t)result == (restart ? 0u : (unsigned)EINTR));
        CHECK(sem_getvalue(fresh, &value) == 0 && value == (restart ? 0 : 1));
        if (!restart) CHECK(sem_trywait(fresh) == 0);
    }
    CHECK(sigaction(SIGUSR1, &previous, NULL) == 0);
    debug("native-named-semaphore-public: signal-handler post, EINTR token preservation and SA_RESTART passed\n");
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) {
        sem_t *reopened = sem_open(name, 0);
        if (reopened != fresh || sem_post(reopened) || sem_close(reopened) || sem_close(fresh)) _exit(1);
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(sem_getvalue(fresh, &value) == 0 && value == 1);
    CHECK(memory_object_count() >= 1);
    char *missing_arguments[] = {"missing", NULL};
    CHECK(execv("/system/services/missing-semaphore-probe", missing_arguments) == -1 && errno == ENOENT);
    CHECK(sem_getvalue(fresh, &value) == 0 && value == 1);
    CHECK(sem_open(name, 0) == fresh && sem_close(fresh) == 0);
    child = fork(); CHECK(child >= 0);
    if (child == 0) {
        char address[32]; snprintf(address, sizeof(address), "%llx", (unsigned long long)(uintptr_t)fresh);
        char *arguments[] = {"semaphore-exec", "--exec-semaphore-child", address, NULL};
        execv("/system/services/compositor.service", arguments);
        _exit(99);
    }
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(sem_getvalue(fresh, &value) == 0 && value == 2);
    CHECK(sem_unlink(name) == 0 && sem_close(fresh) == 0);
    CHECK(sem_open("invalid", 0) == SEM_FAILED && errno == EINVAL);
    CHECK(sem_open("/native-invalid-value", O_CREAT | O_EXCL, (mode_t)0600, SEM_VALUE_MAX + 1u) == SEM_FAILED && errno == EINVAL);
    CHECK(sem_open("/native-invalid-value", 0) == SEM_FAILED && errno == ENOENT);
    CHECK(sem_close(SEM_FAILED) == -1 && errno == EINVAL);
    debug("native-named-semaphore-public: PASS variadic ABI, shared pointers, reference counts, concurrent opens, unlink lifetime, recreation, fork-local close, signal-handler post and exec lifetime\n");
    return 0;
}
