#define SIGNAL_FORK_TEST_ENTRY signal_fork_regression_main
#include "signal_fork_runtime.c"
#undef SIGNAL_FORK_TEST_ENTRY
#undef CHECK
#include <stdatomic.h>
#define CHECK(test) do { if (!(test)) { fprintf(stderr, "upcall-defer: FAIL line=%d errno=%d\n", __LINE__, errno); return 1; } } while (0)
enum { D_INSTALL = 654, D_RETURN = 655, D_THREAD = 656, D_INTERRUPT = 657,
       D_STATUS = 658, D_PROTECT = 584 };
_Static_assert(sizeof(atomic_uint) == 4 && _Alignof(atomic_uint) >= 4, "native defer word ABI");
static unsigned char defer_stack[16384] __attribute__((aligned(4096)));
static volatile unsigned defer_calls, defer_faults;
static uintptr_t defer_fault_address;
static inline uint64_t defer_call(uint64_t number, uint64_t a, uint64_t b, uint64_t c) {
    __asm__ volatile("syscall" : "+a"(number) : "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return number;
}
static void defer_handler(uint64_t payload, uint64_t token, uint64_t kind, uint64_t address) {
    if (kind == 1) {
        if (payload != 14 || address != defer_fault_address
            || defer_call(D_PROTECT, address, 4096, 3)) _exit(91);
        ++defer_faults;
    } else {
        if (payload != 0x55) _exit(92);
        ++defer_calls;
    }
    defer_call(D_RETURN, token, 0, 0);
    _exit(93);
}
static int native_deferral(void) {
    atomic_uint *word = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(word != MAP_FAILED);
    atomic_store_explicit(word, 0, memory_order_relaxed);
    struct {
        uint64_t entry, base, size, flags, defer_word, reserved[3];
    } config = {(uintptr_t)defer_handler, (uintptr_t)defer_stack, sizeof(defer_stack), 1, 0, {0}};
    config.defer_word = 1;
    CHECK((int64_t)defer_call(D_INSTALL, (uintptr_t)&config, sizeof(config), 0) == -22);
    config.defer_word = UINT64_C(0xffff800000000000);
    CHECK((int64_t)defer_call(D_INSTALL, (uintptr_t)&config, sizeof(config), 0) == -22);
    void *missing = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(missing != MAP_FAILED && munmap(missing, 4096) == 0);
    config.defer_word = (uintptr_t)missing;
    CHECK((int64_t)defer_call(D_INSTALL, (uintptr_t)&config, sizeof(config), 0) == -14);
    config.defer_word = (uintptr_t)word;
    CHECK(defer_call(D_INSTALL, (uintptr_t)&config, sizeof(config), 0) == 0);
    uint64_t thread = defer_call(D_THREAD, 0, 0, 0);
    CHECK((int64_t)thread > 0);
    struct { uint64_t thread, process; uint32_t state, reserved; } status;
    atomic_store_explicit(word, 2, memory_order_release);
    CHECK(defer_call(D_INTERRUPT, thread, 0x55, 0) == 0 && defer_calls == 0);
    CHECK(defer_call(D_STATUS, thread, (uintptr_t)&status, 0) == 0 && defer_calls == 0);
    atomic_store_explicit(word, 1, memory_order_release);
    CHECK(defer_call(D_STATUS, thread, (uintptr_t)&status, 0) == 0 && defer_calls == 0);
    atomic_store_explicit(word, 0, memory_order_release);
    CHECK(defer_call(D_STATUS, thread, (uintptr_t)&status, 0) == 0 && defer_calls == 1);
    CHECK(mprotect((void *)word, 4096, PROT_NONE) == 0);
    CHECK(defer_call(D_INTERRUPT, thread, 0x55, 0) == 0 && defer_calls == 1);
    CHECK(defer_call(D_STATUS, thread, (uintptr_t)&status, 0) == 0 && defer_calls == 1);
    CHECK(mprotect((void *)word, 4096, PROT_READ | PROT_WRITE) == 0 && defer_calls == 2);
    unsigned char *fault = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(fault != MAP_FAILED);
    defer_fault_address = (uintptr_t)fault;
    atomic_store_explicit(word, 1, memory_order_release);
    CHECK(defer_call(D_INTERRUPT, thread, 0x55, 0) == 0 && defer_calls == 2);
    *(volatile unsigned char *)fault = 42;
    CHECK(defer_faults == 1 && *fault == 42 && defer_calls == 2);
    atomic_store_explicit(word, 0, memory_order_release);
    CHECK(defer_call(D_STATUS, thread, (uintptr_t)&status, 0) == 0 && defer_calls == 3);
    CHECK(munmap(fault, 4096) == 0);
    puts("upcall-defer: native nesting, unreadable-word retention and synchronous exception bypass PASS");
    return 0;
}

static atomic_uint *stress_shared;
static volatile sig_atomic_t stress_seen, stress_error;
static void stress_handler(int signal) {
    int copied = dup(STDOUT_FILENO);
    if (signal != SIGUSR1 || copied < 0 || close(copied)) stress_error = 1;
    ++stress_seen;
    atomic_store_explicit(stress_shared + 1, (unsigned)stress_seen, memory_order_release);
}
static int runtime_reentry(void) {
    stress_shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(stress_shared != MAP_FAILED);
    atomic_store_explicit(stress_shared, 0, memory_order_relaxed);
    atomic_store_explicit(stress_shared + 1, 0, memory_order_relaxed);
    struct sigaction action = {0};
    action.sa_handler = stress_handler;
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    pid_t parent = getpid(), sender = fork();
    CHECK(sender >= 0);
    if (!sender) {
        for (unsigned round = 1; round <= 32; ++round) {
            if (kill(parent, SIGUSR1)) _exit(94);
            while (atomic_load_explicit(stress_shared + 1, memory_order_acquire) < round) {
                struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000};
                if (nanosleep(&delay, NULL)) _exit(95);
            }
        }
        atomic_store_explicit(stress_shared, 1, memory_order_release);
        _exit(37);
    }
    unsigned operations = 0;
    while (!atomic_load_explicit(stress_shared, memory_order_acquire)) {
        int copied = dup(STDOUT_FILENO);
        CHECK(copied >= 0 && close(copied) == 0);
        ++operations;
    }
    int status;
    CHECK(waitpid(sender, &status, 0) == sender && WIFEXITED(status) && WEXITSTATUS(status) == 37);
    CHECK(stress_seen == 32 && !stress_error && operations > 0);
    CHECK(munmap((void *)stress_shared, 4096) == 0);
    puts("upcall-defer: runtime dup/close reentry across 32 acknowledged asynchronous handlers PASS");
    return 0;
}
static int default_stop_reentry(void) {
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        if (raise(SIGSTOP)) _exit(97);
        _exit(37);
    }
    int status;
    CHECK(waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status)
        && WSTOPSIG(status) == SIGSTOP);
    CHECK(kill(child, SIGCONT) == 0);
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 37);
    puts("upcall-defer: prepared default stop resumes on SIGCONT PASS");
    return 0;
}
#ifndef UPCALL_DEFER_TEST_ENTRY
#define UPCALL_DEFER_TEST_ENTRY main
#endif
int UPCALL_DEFER_TEST_ENTRY(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--after-exec"))
        return signal_fork_regression_main(argc, argv);
    sigset_t mask;
    sigemptyset(&mask); sigaddset(&mask, SIGCHLD);
    CHECK(sigprocmask(SIG_BLOCK, &mask, NULL) == 0);
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) _exit(native_deferral() ? 96 : 37);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 37);
    CHECK(sigprocmask(SIG_UNBLOCK, &mask, NULL) == 0);
    CHECK(runtime_reentry() == 0);
    CHECK(default_stop_reentry() == 0);
    CHECK(signal_fork_regression_main(argc, argv) == 0);
    puts("upcall-defer: PASS native deferral, runtime reentry and complete signal/fork regressions");
    return 0;
}
