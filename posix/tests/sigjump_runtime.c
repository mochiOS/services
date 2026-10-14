#define UPCALL_DEFER_TEST_ENTRY upcall_defer_regression_main
#include "upcall_defer_runtime.c"
#undef UPCALL_DEFER_TEST_ENTRY
#undef CHECK
#include <setjmp.h>
#define CHECK(test) do { if (!(test)) { fprintf(stderr, "sigjump: FAIL line=%d errno=%d\n", __LINE__, errno); return 1; } } while (0)
_Static_assert(sizeof(sigjmp_buf) == 120, "signal jump ABI");
static sigjmp_buf sj_escape;
static volatile sig_atomic_t sj_action, sj_seen, sj_error, sj_child, sj_nested_done;
static volatile pid_t sj_descendant;
static unsigned char sj_stack[SIGSTKSZ * 32] __attribute__((aligned(4096)));
static volatile unsigned *sj_ready;

static void sj_handler(int signal) {
    ++sj_seen;
    if (sj_action == 0) return;
    if (sj_action == 5) {
        if (sigsetjmp(sj_escape, 0)) _exit(95);
        return;
    }
    if (sj_action == 2 && signal == SIGUSR1) {
        sigjmp_buf local;
        int result = sigsetjmp(local, 1);
        if (!result) {
            /* Only the inner handler uses this live outer environment. */
            memcpy(sj_escape, local, sizeof(local));
            if (raise(SIGUSR2)) sj_error = 1;
            sj_error = 2;
        } else {
            sigset_t mask;
            if (result != 41 || sigprocmask(SIG_SETMASK, NULL, &mask)
                || !sigismember(&mask, SIGUSR1) || sigismember(&mask, SIGUSR2)) sj_error = 3;
            sj_nested_done = 1;
        }
        return;
    }
    if (sj_action == 3) {
        pid_t child = fork();
        if (child < 0) { sj_error = 4; return; }
        sj_descendant = child;
        if (!child) sj_child = 1;
    }
    if (sj_action == 4) {
        unsigned mxcsr = 0x3f80;
        __asm__ volatile("ldmxcsr %0" : : "m"(mxcsr));
    }
    siglongjmp(sj_escape, 41);
}
static void sj_typed(int signal, siginfo_t *info, void *context) {
    if (!info || !context || info->si_signo != signal) { sj_error = 5; return; }
    sj_handler(signal);
}
static int sj_install(int typed, int alternate) {
    struct sigaction action = {0};
    sigemptyset(&action.sa_mask);
    action.sa_flags = (typed ? SA_SIGINFO : 0) | (alternate ? SA_ONSTACK : 0);
    if (typed) action.sa_sigaction = sj_typed;
    else action.sa_handler = sj_handler;
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    CHECK(sigaction(SIGUSR2, &action, NULL) == 0);
    return 0;
}
static int sj_clean_mask(void) {
    sigset_t mask;
    sigemptyset(&mask);
    CHECK(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);
    return 0;
}
static int sj_values_and_masks(void) {
    CHECK(sj_clean_mask() == 0);
    for (volatile int value = 0; value < 3; ++value) {
        sigjmp_buf environment;
        int result = sigsetjmp(environment, 0);
        if (!result) siglongjmp(environment, value == 0 ? 0 : value == 1 ? 37 : -7);
        CHECK(result == (value == 0 ? 1 : value == 1 ? 37 : -7));
    }
    for (volatile int save = 0; save < 2; ++save) {
        sigset_t initial, changed, mask;
        sigemptyset(&initial); sigaddset(&initial, SIGUSR2);
        sigemptyset(&changed); sigaddset(&changed, SIGUSR1);
        CHECK(sigprocmask(SIG_SETMASK, &initial, NULL) == 0);
        sigjmp_buf environment;
        int result = sigsetjmp(environment, save);
        if (!result) {
            CHECK(sigprocmask(SIG_SETMASK, &changed, NULL) == 0);
            siglongjmp(environment, 37);
        }
        CHECK(result == 37 && sigprocmask(SIG_SETMASK, NULL, &mask) == 0);
        CHECK(sigismember(&mask, SIGUSR1) == !save);
        CHECK(sigismember(&mask, SIGUSR2) == save);
    }
    CHECK(sj_clean_mask() == 0);
    puts("sigjump: return values and optional saved masks PASS");
    return 0;
}
static int sj_sync(void) {
    stack_t stack = {.ss_sp = sj_stack, .ss_size = sizeof(sj_stack)};
    CHECK(sigaltstack(&stack, NULL) == 0);
    for (volatile int mode = 0; mode < 8; ++mode) {
        CHECK(sj_install(mode & 1, mode & 2) == 0);
        for (volatile int iteration = 0; iteration < 80; ++iteration) {
            sj_seen = sj_error = 0; sj_action = 1;
            int result = sigsetjmp(sj_escape, !(mode & 4));
            if (!result) { CHECK(raise(SIGUSR1) == 0); CHECK(0); }
            CHECK(result == 41 && sj_seen == 1 && !sj_error);
            sigset_t mask; stack_t current;
            CHECK(sigprocmask(SIG_SETMASK, NULL, &mask) == 0
                && sigismember(&mask, SIGUSR1) == !!(mode & 4));
            CHECK(sigaltstack(NULL, &current) == 0 && !(current.ss_flags & SS_ONSTACK));
            sj_action = 0;
            CHECK(sj_clean_mask() == 0);
            CHECK(raise(SIGUSR1) == 0 && sj_seen == 2);
        }
        sj_action = 2; sj_seen = sj_error = sj_nested_done = 0;
        CHECK(raise(SIGUSR1) == 0 && sj_seen == 2 && sj_nested_done && !sj_error);
    }
    stack.ss_flags = SS_DISABLE;
    CHECK(sigaltstack(&stack, NULL) == 0);
    puts("sigjump: repeated legacy/typed/alternate and selective nested handler jumps PASS");
    return 0;
}
static int sj_async_or_fork(int asynchronous, int action, int alternate) {
    CHECK(sj_install(1, alternate) == 0);
    stack_t stack = {.ss_sp = sj_stack, .ss_size = sizeof(sj_stack)};
    if (alternate) CHECK(sigaltstack(&stack, NULL) == 0);
    sj_action = action; sj_seen = sj_error = sj_child = sj_nested_done = 0;
    sj_descendant = -1;
    atomic_store_explicit(sj_ready, 0, memory_order_release);
    pid_t sender = -1;
    if (asynchronous) {
        pid_t parent = getpid();
        sender = fork(); CHECK(sender >= 0);
        if (!sender) {
            while (!atomic_load_explicit(sj_ready, memory_order_acquire)) {}
            if (kill(parent, SIGUSR1)) _exit(94);
            _exit(37);
        }
    }
    unsigned old_mxcsr;
    __asm__ volatile("stmxcsr %0" : "=m"(old_mxcsr));
    int result = sigsetjmp(sj_escape, 1);
    if (!result) {
        if (asynchronous) {
            atomic_store_explicit(sj_ready, 1, memory_order_release);
            while (!sj_nested_done) __asm__ volatile("" : : : "memory");
            CHECK(action == 2);
        } else {
            CHECK(raise(SIGUSR1) == 0);
            CHECK(action == 2);
        }
    } else CHECK(result == 41 && action != 2);
    if (action == 4) {
        unsigned mxcsr;
        __asm__ volatile("stmxcsr %0" : "=m"(mxcsr));
        CHECK(mxcsr == 0x3f80);
        __asm__ volatile("ldmxcsr %0" : : "m"(old_mxcsr));
    }
    CHECK(!sj_error && sj_seen == (action == 2 ? 2 : 1));
    sj_action = 0;
    CHECK(raise(SIGUSR1) == 0); /* Fresh delivery after leaving native upcall. */
    if (sj_child) _exit(37);
    int status;
    if (action == 3) CHECK(waitpid(sj_descendant, &status, 0) == sj_descendant
        && WIFEXITED(status) && WEXITSTATUS(status) == 37);
    if (sender >= 0) CHECK(waitpid(sender, &status, 0) == sender
        && WIFEXITED(status) && WEXITSTATUS(status) == 37);
    if (alternate) { stack.ss_flags = SS_DISABLE; CHECK(sigaltstack(&stack, NULL) == 0); }
    printf("sigjump: async=%d action=%d alternate=%d PASS\n", asynchronous, action, alternate);
    return 0;
}
static void *sj_wrong_thread(void *unused) { (void)unused; siglongjmp(sj_escape, 1); }
static int sj_invalid_targets(void) {
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        if (sigsetjmp(sj_escape, 0)) _exit(95);
        pthread_t thread;
        if (pthread_create(&thread, NULL, sj_wrong_thread, NULL)) _exit(96);
        pthread_join(thread, NULL); _exit(97);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == EINVAL);
    child = fork(); CHECK(child >= 0);
    if (!child) {
        if (sj_install(0, 0)) _exit(96);
        sj_action = 5;
        if (raise(SIGUSR1)) _exit(97);
        siglongjmp(sj_escape, 1); /* The saved handler has already returned. */
    }
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == EINVAL);
    puts("sigjump: wrong-thread and retired-handler environments rejected PASS");
    return 0;
}
static int sj_fault_escape(void) {
    struct sigaction action = {0};
    action.sa_sigaction = sj_typed; action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
    sj_action = 1; sj_seen = sj_error = 0;
    if (!sigsetjmp(sj_escape, 1)) { (void)siginfo_fault(); CHECK(0); }
    CHECK(sj_seen == 1 && !sj_error);
    sj_action = 0;
    CHECK(raise(SIGSEGV) == 0 && sj_seen == 2);
    puts("sigjump: synchronous fault escape and fresh delivery PASS");
    return 0;
}
static void sj_minimum_handler(int signal) { (void)signal; siglongjmp(sj_escape, 37); }
static int sj_minimum_stack(void) {
    unsigned char *mapping = mmap(NULL, 3 * 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(mapping != MAP_FAILED && mprotect(mapping + 4096, 4096, PROT_READ | PROT_WRITE) == 0);
    stack_t stack = {.ss_sp = mapping + 4096, .ss_size = MINSIGSTKSZ};
    CHECK(sigaltstack(&stack, NULL) == 0);
    struct sigaction action = {0};
    action.sa_handler = sj_minimum_handler; action.sa_flags = SA_ONSTACK;
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    for (volatile int asynchronous = 0; asynchronous < 2; ++asynchronous) {
        atomic_store_explicit(sj_ready, 0, memory_order_release);
        pid_t sender = -1;
        if (asynchronous) {
            pid_t parent = getpid();
            sender = fork(); CHECK(sender >= 0);
            if (!sender) {
                while (!atomic_load_explicit(sj_ready, memory_order_acquire)) {}
                if (kill(parent, SIGUSR1)) _exit(94);
                _exit(37);
            }
        }
        int result = sigsetjmp(sj_escape, 1);
        if (!result) {
            if (!asynchronous) { CHECK(raise(SIGUSR1) == 0); CHECK(0); }
            atomic_store_explicit(sj_ready, 1, memory_order_release);
            for (;;) __asm__ volatile("" : : : "memory");
        }
        CHECK(result == 37);
        int status;
        if (sender >= 0) CHECK(waitpid(sender, &status, 0) == sender && WIFEXITED(status) && WEXITSTATUS(status) == 37);
    }
    stack.ss_flags = SS_DISABLE;
    CHECK(sigaltstack(&stack, NULL) == 0 && munmap(mapping, 3 * 4096) == 0);
    puts("sigjump: guarded minimum stack, sync and native async escape PASS");
    return 0;
}
static volatile sig_atomic_t sj_chain_depth, sj_chain_error;
static volatile pid_t sj_chain_descendant, sj_chain_sender;
static void sj_chain_handler(int signal) {
    pid_t child = fork();
    if (child < 0) { sj_chain_error = 1; return; }
    sj_chain_descendant = child;
    if (!child) ++sj_chain_depth;
    if (signal == SIGUSR1 && !child) {
        /* Keep copied frame A live while a genuinely asynchronous callback B
           arrives on the child's freshly registered private stack. */
        sj_chain_descendant = 0;
        atomic_store_explicit(sj_ready, 0, memory_order_release);
        pid_t parent = getpid();
        pid_t sender = fork();
        if (sender < 0) { sj_chain_error = 2; return; }
        if (!sender) {
            while (!atomic_load_explicit(sj_ready, memory_order_acquire)) {}
            if (kill(parent, SIGUSR2)) _exit(94);
            _exit(37);
        }
        sj_chain_sender = sender;
        atomic_store_explicit(sj_ready, 1, memory_order_release);
        for (;;) __asm__ volatile("" : : : "memory");
    }
    siglongjmp(sj_escape, 41);
}
static int sj_orphan_chain(void) {
    struct sigaction action = {0};
    action.sa_handler = sj_chain_handler;
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0 && sigaction(SIGUSR2, &action, NULL) == 0);
    sj_chain_depth = sj_chain_error = 0;
    sj_chain_descendant = sj_chain_sender = 0;
    atomic_store_explicit(sj_ready, 0, memory_order_release);
    /* Force callback A through the native path too; raise alone may drain via
       the synchronous userspace checkpoint before an interrupt is prepared. */
    pid_t parent = getpid(), initial_sender = fork();
    CHECK(initial_sender >= 0);
    if (!initial_sender) {
        while (!atomic_load_explicit(sj_ready, memory_order_acquire)) {}
        if (kill(parent, SIGUSR1)) _exit(94);
        _exit(37);
    }
    int result = sigsetjmp(sj_escape, 1);
    if (!result) {
        atomic_store_explicit(sj_ready, 1, memory_order_release);
        for (;;) __asm__ volatile("" : : : "memory");
    }
    CHECK(result == 41 && !sj_chain_error && sj_chain_depth <= 2);
    /* Every descendant must be able to deliver again after the old chain was
       reclaimed. Neither parent's return token belongs to the grandchild. */
    CHECK(sj_install(0, 0) == 0); sj_action = 0; sj_seen = 0;
    CHECK(raise(SIGUSR1) == 0 && sj_seen == 1);
    int status;
    if (sj_chain_descendant > 0) CHECK(waitpid(sj_chain_descendant, &status, 0) == sj_chain_descendant
        && WIFEXITED(status) && WEXITSTATUS(status) == 37);
    if (sj_chain_depth == 1) CHECK(waitpid(sj_chain_sender, &status, 0) == sj_chain_sender
        && WIFEXITED(status) && WEXITSTATUS(status) == 37);
    printf("sigjump: copied chain depth=%d, fresh handler and descendant cleanup PASS\n", sj_chain_depth);
    if (sj_chain_depth > 0) _exit(37);
    CHECK(waitpid(initial_sender, &status, 0) == initial_sender && WIFEXITED(status) && WEXITSTATUS(status) == 37);
    puts("sigjump: two copied native frames reclaimed after destination switch PASS");
    return 0;
}
#ifndef SIGJUMP_TEST_ENTRY
#define SIGJUMP_TEST_ENTRY main
#endif
int SIGJUMP_TEST_ENTRY(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--after-exec")) return upcall_defer_regression_main(argc, argv);
    CHECK(sj_values_and_masks() == 0);
    CHECK(sj_sync() == 0);
    CHECK(sj_fault_escape() == 0);
    sj_ready = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(sj_ready != MAP_FAILED);
    CHECK(sj_minimum_stack() == 0);
    CHECK(sj_orphan_chain() == 0);
    for (int asynchronous = 0; asynchronous < 2; ++asynchronous)
        for (int alternate = 0; alternate < 2; ++alternate) {
            CHECK(sj_async_or_fork(asynchronous, 3, alternate) == 0);
            CHECK(sj_async_or_fork(asynchronous, 2, alternate) == 0);
            CHECK(sj_async_or_fork(asynchronous, 4, alternate) == 0);
        }
    CHECK(munmap((void *)sj_ready, 4096) == 0);
    CHECK(sj_invalid_targets() == 0);
    CHECK(upcall_defer_regression_main(argc, argv) == 0);
    puts("sigjump: PASS nonlocal signal restoration and complete signal regressions");
    return 0;
}
