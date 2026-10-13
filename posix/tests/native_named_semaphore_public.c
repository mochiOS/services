#include <semaphore.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *name = "/native-semaphore-public";
static sem_t *expected;
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
int main(void) {
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
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) {
        sem_t *reopened = sem_open(name, 0);
        if (reopened != fresh || sem_post(reopened) || sem_close(reopened) || sem_close(fresh)) _exit(1);
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(sem_getvalue(fresh, &value) == 0 && value == 1);
    CHECK(sem_unlink(name) == 0 && sem_close(fresh) == 0);
    CHECK(sem_open("invalid", 0) == SEM_FAILED && errno == EINVAL);
    CHECK(sem_open("/native-invalid-value", O_CREAT | O_EXCL, (mode_t)0600, SEM_VALUE_MAX + 1u) == SEM_FAILED && errno == EINVAL);
    CHECK(sem_open("/native-invalid-value", 0) == SEM_FAILED && errno == ENOENT);
    CHECK(sem_close(SEM_FAILED) == -1 && errno == EINVAL);
    debug("native-named-semaphore-public: PASS variadic ABI, shared pointers, reference counts, concurrent opens, unlink lifetime, recreation and fork-local close\n");
    return 0;
}
