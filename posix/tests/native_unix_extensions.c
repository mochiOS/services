/* Actual public C APIs on mochiOS, using ordinary process/file Capabilities.
   Build once as the probe, and once with UNIX_EXEC_HELPER as its exec helper. */
#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { \
    printf("unix-api FAIL line=%d errno=%d\n", __LINE__, errno); return 1; \
} } while (0)
static const char *lock_path = "/tmp/unix-api-lock";

#ifdef UNIX_EXEC_HELPER
int main(void)
{
    const char *number = getenv("MOCHI_UNIX_LOCK_FD");
    const char *mode = getenv("MOCHI_UNIX_LOCK_MODE");
    CHECK(number && mode);
    int fd = atoi(number);
    if (!strcmp(mode, "close")) {
        errno = 0;
        CHECK(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
    } else {
        CHECK(fcntl(fd, F_GETFD) >= 0);
    }
    int other = open(lock_path, O_RDONLY);
    CHECK(other >= 0);
    if (strcmp(mode, "close")) {
        errno = 0;
        CHECK(flock(other, LOCK_EX | LOCK_NB) == -1 && errno == EWOULDBLOCK);
        CHECK(close(fd) == 0);
    }
    CHECK(flock(other, LOCK_EX | LOCK_NB) == 0);
    CHECK(close(other) == 0);
    puts("unix-api exec-helper PASS");
    return 0;
}
#else
static const char *library_path = "/system/libraries/port-smoke/libunix-inspection.so";
static int success(pid_t child)
{
    int status = -1;
    return waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
static int send_byte(int fd, char value) { return write(fd, &value, 1) == 1; }
static int receive_byte(int fd, char expected)
{
    char value = 0;
    return read(fd, &value, 1) == 1 && value == expected;
}
static int file_locks(void)
{
    unlink(lock_path);
    int a = open(lock_path, O_CREAT | O_EXCL | O_RDWR, (mode_t)0600);
    CHECK(a >= 0);
    int alias = dup(a), other = open(lock_path, O_RDONLY);
    CHECK(alias >= 0 && other >= 0);
    CHECK(flock(a, LOCK_EX | LOCK_NB) == 0);
    CHECK(flock(alias, LOCK_EX | LOCK_NB) == 0);
    errno = 0;
    CHECK(flock(other, LOCK_SH | LOCK_NB) == -1 && errno == EWOULDBLOCK);
    CHECK(flock(a, LOCK_SH) == 0);
    CHECK(flock(other, LOCK_SH) == 0);
    errno = 0;
    CHECK(flock(a, LOCK_EX | LOCK_NB) == -1 && errno == EWOULDBLOCK);
    /* Failed conversion must release A's old shared lock. */
    CHECK(flock(other, LOCK_EX | LOCK_NB) == 0);
    CHECK(flock(other, LOCK_UN) == 0 && flock(a, LOCK_EX) == 0);
    int commands[2], replies[2];
    CHECK(pipe(commands) == 0 && pipe(replies) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        close(commands[1]); close(replies[0]);
        int result = close(a) || close(alias) || !send_byte(replies[1], 'R')
            || !receive_byte(commands[0], 'G') || flock(other, LOCK_EX | LOCK_NB)
            || !send_byte(replies[1], 'S') || close(other);
        _exit(result != 0);
    }
    close(commands[0]); close(replies[1]);
    CHECK(receive_byte(replies[0], 'R'));
    CHECK(close(a) == 0);
    errno = 0;
    CHECK(flock(other, LOCK_EX | LOCK_NB) == -1 && errno == EWOULDBLOCK);
    CHECK(close(alias) == 0 && send_byte(commands[1], 'G'));
    CHECK(receive_byte(replies[0], 'S') && success(child));
    close(commands[1]); close(replies[0]);
    /* The child's lock belongs to the OFD still retained by parent 'other'. */
    a = open(lock_path, O_RDWR);
    CHECK(a >= 0);
    errno = 0;
    CHECK(flock(a, LOCK_EX | LOCK_NB) == -1 && errno == EWOULDBLOCK);
    CHECK(flock(other, LOCK_UN) == 0 && flock(a, LOCK_EX | LOCK_NB) == 0);
    CHECK(close(a) == 0 && close(other) == 0);
    puts("unix-api flock dup/fork/conversion/final-reference PASS");
    return 0;
}

static int exec_locks(int close_on_exec)
{
    int fd = open(lock_path, O_RDWR), commands[2];
    CHECK(fd >= 0 && pipe(commands) == 0 && flock(fd, LOCK_EX) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        close(commands[1]);
        if (close_on_exec && fcntl(fd, F_SETFD, FD_CLOEXEC)) _exit(81);
        char number[24];
        snprintf(number, sizeof(number), "%d", fd);
        if (setenv("MOCHI_UNIX_LOCK_FD", number, 1)
            || setenv("MOCHI_UNIX_LOCK_MODE", close_on_exec ? "close" : "retain", 1)
            || !receive_byte(commands[0], 'G')) _exit(82);
        close(commands[0]);
        char *arguments[] = { "/system/bin/unix-extension-child", NULL };
        execv(arguments[0], arguments);
        _exit(83);
    }
    close(commands[0]);
    /* Sole ownership moves to the child before exec. The parent cannot hide
       a lost child lock by accidentally retaining its own native reference. */
    CHECK(close(fd) == 0 && send_byte(commands[1], 'G'));
    close(commands[1]);
    CHECK(success(child));
    puts(close_on_exec ? "unix-api flock CLOEXEC PASS" : "unix-api flock exec inheritance PASS");
    return 0;
}

static atomic_int started, finished;
static int waiting_fd, wait_result, wait_errno;
static void ignore_signal(int signal) { (void)signal; }
static void *wait_for_lock(void *unused)
{
    (void)unused;
    atomic_store(&started, 1);
    wait_result = flock(waiting_fd, LOCK_EX);
    wait_errno = errno;
    atomic_store(&finished, 1);
    return NULL;
}
static int blocking_locks(int interrupt)
{
    int commands[2], replies[2];
    CHECK(pipe(commands) == 0 && pipe(replies) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        close(commands[1]); close(replies[0]);
        int fd = open(lock_path, O_RDONLY);
        int result = fd < 0 || flock(fd, LOCK_EX) || !send_byte(replies[1], 'R')
            || !receive_byte(commands[0], 'E');
        /* No explicit unlock/close: native process teardown must release it. */
        _exit(result != 0);
    }
    close(commands[0]); close(replies[1]);
    CHECK(receive_byte(replies[0], 'R'));
    waiting_fd = open(lock_path, O_RDONLY);
    CHECK(waiting_fd >= 0);
    struct sigaction action = {0};
    action.sa_handler = ignore_signal;
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    atomic_store(&started, 0); atomic_store(&finished, 0);
    pthread_t worker;
    CHECK(pthread_create(&worker, NULL, wait_for_lock, NULL) == 0);
    while (!atomic_load(&started)) usleep(1000);
    if (interrupt) {
        for (int i = 0; i < 100 && !atomic_load(&finished); ++i) {
            usleep(2000);
            int error = pthread_kill(worker, SIGUSR1);
            CHECK(error == 0 || error == ESRCH);
        }
    }
    int interrupted = atomic_load(&finished);
    CHECK(send_byte(commands[1], 'E') && success(child));
    CHECK(pthread_join(worker, NULL) == 0);
    if (interrupt) CHECK(interrupted && wait_result == -1 && wait_errno == EINTR);
    else CHECK(wait_result == 0);
    CHECK(close(waiting_fd) == 0);
    close(commands[1]); close(replies[0]);
    puts(interrupt ? "unix-api flock signal interruption PASS" : "unix-api flock process-exit wake PASS");
    return 0;
}

static int memory_observation(void)
{
    const size_t page = 4096;
    unsigned char vector[2] = {0, 0};
    volatile unsigned char *memory = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK((void *)memory != MAP_FAILED);
    memory[0] = 71; memory[page] = 89;
    CHECK(mincore((void *)memory, page * 2, vector) == 0 && (vector[0] & 1) && (vector[1] & 1));
    CHECK(mprotect((void *)memory, page, PROT_NONE) == 0);
    CHECK(mincore((void *)memory, page, vector) == 0 && (vector[0] & 1));
    CHECK(mprotect((void *)memory, page, PROT_READ) == 0);
    CHECK(madvise((void *)memory, 1, MADV_DONTNEED) == 0);
    CHECK(memory[0] == 0 && memory[page] == 89);
    int pipefd[2];
    CHECK(pipe(pipefd) == 0 && send_byte(pipefd[1], 'W'));
    errno = 0;
    CHECK(read(pipefd[0], (void *)memory, 1) == -1 && errno == EFAULT);
    CHECK(close(pipefd[0]) == 0 && close(pipefd[1]) == 0);
    CHECK(mprotect((void *)memory, page, PROT_READ | PROT_WRITE) == 0);
    memory[0] = 0x5a;
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) _exit(madvise((void *)memory, page, MADV_DONTNEED) || memory[0] != 0);
    CHECK(success(child) && memory[0] == 0x5a);
    errno = 0;
    CHECK(mincore((void *)(memory + 1), 1, vector) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(mincore((void *)memory, 1, (unsigned char *)1) == -1 && errno == EFAULT);
    errno = 0;
    CHECK(madvise((void *)(memory + 1), 1, MADV_DONTNEED) == -1 && errno == EINVAL);
    CHECK(munmap((void *)(memory + page), page) == 0);
    errno = 0;
    CHECK(mincore((void *)memory, page * 2, vector) == -1 && errno == ENOMEM);
    CHECK(munmap((void *)memory, page) == 0);
    void *shared = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(shared != MAP_FAILED);
    *(volatile unsigned char *)shared = 19;
    errno = 0;
    CHECK(madvise(shared, page, MADV_DONTNEED) == -1 && errno == ENOTSUP);
    CHECK(*(volatile unsigned char *)shared == 19 && munmap(shared, page) == 0);
    int fd = open(lock_path, O_RDWR);
    CHECK(fd >= 0 && ftruncate(fd, page) == 0 && write(fd, "F", 1) == 1);
    memory = mmap(NULL, page, PROT_READ, MAP_PRIVATE, fd, 0);
    CHECK((void *)memory != MAP_FAILED && memory[0] == 'F');
    CHECK(munmap((void *)memory, page) == 0);
    memory = mmap(NULL, page, PROT_READ, MAP_PRIVATE, fd, 0);
    CHECK((void *)memory != MAP_FAILED);
    CHECK(mincore((void *)memory, page, vector) == 0 && (vector[0] & 1));
    errno = 0;
    CHECK(madvise((void *)memory, page, MADV_DONTNEED) == -1 && errno == ENOTSUP);
    CHECK(memory[0] == 'F' && munmap((void *)memory, page) == 0 && close(fd) == 0);
    puts("unix-api memory residency/discard/protection/COW/errors/cache PASS");
    return 0;
}

struct inspection { int libraries, total, close_on_visit; void *handle; };
static int inspect_object(struct dl_phdr_info *info, size_t size, void *data)
{
    struct inspection *context = data;
    if (size < sizeof(*info) || !info->dlpi_phdr || !info->dlpi_phnum || !info->dlpi_name) return 91;
    ++context->total;
    if (strstr(info->dlpi_name, "libunix-inspection.so")) {
        ++context->libraries;
        if (context->close_on_visit) {
            context->close_on_visit = 0;
            if (dlclose(context->handle)) return 92;
            /* The iterator's copied name/headers must survive this unload. */
            if (!strstr(info->dlpi_name, "libunix-inspection.so") || info->dlpi_phnum == 0) return 93;
        }
    }
    return 0;
}
static int loader_inspection(void)
{
    struct inspection before = {0};
    CHECK(dl_iterate_phdr(inspect_object, &before) == 0 && before.total > 0 && before.libraries == 0);
    for (int pass = 0; pass < 2; ++pass) {
        void *handle = dlopen(library_path, RTLD_NOW | RTLD_LOCAL);
        if (!handle) printf("unix-api dlopen: %s\n", dlerror());
        CHECK(handle != NULL);
        int (*evaluate)(int) = (int (*)(int))dlsym(handle, "native_unix_value");
        int (*constructed)(void) = (int (*)(void))dlsym(handle, "native_unix_constructor_result");
        CHECK(evaluate && constructed && evaluate(7) == 130 && constructed() == 1);
        double (*math_result)(void) = (double (*)(void))dlsym(handle, "native_unix_math_result");
        CHECK(math_result && math_result() == 15.0);
        int (*integer_result)(void) = (int (*)(void))dlsym(handle, "native_unix_integer_result");
        CHECK(integer_result && integer_result());
        Dl_info info;
        CHECK(dladdr((void *)(uintptr_t)evaluate, &info) == 1 && info.dli_fname && info.dli_fbase
            && info.dli_sname && !strcmp(info.dli_sname, "native_unix_value")
            && info.dli_saddr == (void *)(uintptr_t)evaluate);
        struct inspection current = {0};
        CHECK(dl_iterate_phdr(inspect_object, &current) == 0 && current.libraries == 1);
        uintptr_t old = (uintptr_t)evaluate;
        if (pass) {
            current = (struct inspection){ .close_on_visit = 1, .handle = handle };
            CHECK(dl_iterate_phdr(inspect_object, &current) == 0 && current.libraries == 1 && !current.close_on_visit);
        } else CHECK(dlclose(handle) == 0);
        CHECK(dladdr((void *)old, &info) == 0);
        current = (struct inspection){0};
        CHECK(dl_iterate_phdr(inspect_object, &current) == 0 && current.libraries == 0 && current.total == before.total);
    }
    puts("unix-api loader initial/constructor-reentry/symbol/unload/snapshot PASS");
    return 0;
}

int native_unix_extensions_probe(void)
{
    alarm(180);
    puts("unix-api begin");
    struct sched_param parameter = {0};
    int policy = -1;
    errno = 57;
    CHECK(pthread_getschedparam(pthread_self(), &policy, &parameter) == 0
        && policy == SCHED_OTHER && parameter.sched_priority == 0 && errno == 57);
    CHECK(pthread_setschedparam(pthread_self(), SCHED_OTHER, &parameter) == 0 && errno == 57);
    parameter.sched_priority = 1;
    CHECK(pthread_setschedparam(pthread_self(), SCHED_FIFO, &parameter) == ENOTSUP && errno == 57);
    puts("unix-api pthread scheduling PASS");
    CHECK(file_locks() == 0);
    CHECK(exec_locks(0) == 0 && exec_locks(1) == 0);
    CHECK(blocking_locks(0) == 0 && blocking_locks(1) == 0);
    CHECK(memory_observation() == 0);
    CHECK(loader_inspection() == 0);
    CHECK(unlink(lock_path) == 0);
    alarm(0);
    puts("unix-api ALL PASS");
    return 0;
}
#endif
