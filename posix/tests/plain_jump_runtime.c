#define SIGJUMP_TEST_ENTRY sigjump_regression_main
#include "sigjump_runtime.c"
#undef SIGJUMP_TEST_ENTRY
#undef CHECK
#define CHECK(test) do { if (!(test)) { fprintf(stderr, "plain-jump: FAIL line=%d errno=%d\n", __LINE__, errno); return 1; } } while (0)
_Static_assert(sizeof(jmp_buf) == sizeof(sigjmp_buf), "unified jump ABI");
static jmp_buf pj_escape;
static volatile sig_atomic_t pj_entry, pj_action, pj_seen, pj_error, pj_child, pj_done;
static volatile pid_t pj_descendant;
#define PJ_SAVE(buffer) ((pj_entry & 1) ? _setjmp(buffer) : setjmp(buffer))
#define PJ_JUMP(buffer, value) do { if (pj_entry & 2) _longjmp(buffer, value); longjmp(buffer, value); } while (0)

static void pj_handler(int signal) {
    ++pj_seen;
    if (!pj_action) return;
    if (pj_action == 2 && signal == SIGUSR1) {
        jmp_buf local;
        int result = PJ_SAVE(local);
        if (!result) {
            memcpy(pj_escape, local, sizeof(local));
            if (raise(SIGUSR2)) pj_error = 1;
            pj_error = 2;
        } else {
            sigset_t mask;
            if (result != 41 || sigprocmask(SIG_SETMASK, NULL, &mask)
                || !sigismember(&mask, SIGUSR1) || !sigismember(&mask, SIGUSR2)) pj_error = 3;
            pj_done = 1;
        }
        return;
    }
    if (pj_action == 3) {
        pid_t child = fork();
        if (child < 0) { pj_error = 4; return; }
        pj_descendant = child;
        if (!child) pj_child = 1;
    }
    PJ_JUMP(pj_escape, 41);
}
static int pj_install(int alternate) {
    struct sigaction action = {0};
    action.sa_handler = pj_handler;
    action.sa_flags = alternate ? SA_ONSTACK : 0;
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0 && sigaction(SIGUSR2, &action, NULL) == 0);
    return 0;
}
static int pj_values_and_sync(void) {
    CHECK(sj_clean_mask() == 0);
    for (pj_entry = 0; pj_entry < 4; ++pj_entry) {
        for (volatile int value = 0; value < 3; ++value) {
            jmp_buf environment;
            int result = PJ_SAVE(environment);
            if (!result) PJ_JUMP(environment, value == 0 ? 0 : value == 1 ? 37 : -7);
            CHECK(result == (value == 0 ? 1 : value == 1 ? 37 : -7));
        }
        CHECK(pj_install(0) == 0);
        for (volatile int iteration = 0; iteration < 80; ++iteration) {
            pj_seen = pj_error = 0; pj_action = 1;
            int result = PJ_SAVE(pj_escape);
            if (!result) { CHECK(raise(SIGUSR1) == 0); CHECK(0); }
            CHECK(result == 41 && pj_seen == 1 && !pj_error);
            sigset_t mask;
            CHECK(sigprocmask(SIG_SETMASK, NULL, &mask) == 0 && sigismember(&mask, SIGUSR1));
            pj_action = 0;
            CHECK(sj_clean_mask() == 0 && raise(SIGUSR1) == 0 && pj_seen == 2);
        }
        pj_action = 2; pj_seen = pj_error = pj_done = 0;
        CHECK(raise(SIGUSR1) == 0 && pj_seen == 2 && pj_done && !pj_error);
        sigset_t mask;
        CHECK(sigprocmask(SIG_SETMASK, NULL, &mask) == 0 && !sigismember(&mask, SIGUSR1)
            && !sigismember(&mask, SIGUSR2));
    }
    puts("plain-jump: all entrypoint pairs, return values, repeated delivery, unsaved masks and nested jumps PASS");
    return 0;
}
static int pj_native_or_fork(int asynchronous, int alternate, int fork_handler) {
    CHECK(pj_install(alternate) == 0);
    stack_t stack = {.ss_sp = sj_stack, .ss_size = sizeof(sj_stack)};
    if (alternate) CHECK(sigaltstack(&stack, NULL) == 0);
    pj_action = fork_handler ? 3 : 1;
    pj_seen = pj_error = pj_child = 0; pj_descendant = -1;
    pid_t sender = -1;
    atomic_store_explicit(sj_ready, 0, memory_order_release);
    if (asynchronous) {
        pid_t parent = getpid(); sender = fork(); CHECK(sender >= 0);
        if (!sender) {
            while (!atomic_load_explicit(sj_ready, memory_order_acquire)) {}
            if (kill(parent, SIGUSR1)) _exit(94);
            _exit(37);
        }
    }
    int result = PJ_SAVE(pj_escape);
    if (!result) {
        if (!asynchronous) { CHECK(raise(SIGUSR1) == 0); CHECK(0); }
        atomic_store_explicit(sj_ready, 1, memory_order_release);
        for (;;) __asm__ volatile("" : : : "memory");
    }
    CHECK(result == 41 && pj_seen == 1 && !pj_error);
    sigset_t mask;
    CHECK(sigprocmask(SIG_SETMASK, NULL, &mask) == 0 && sigismember(&mask, SIGUSR1));
    pj_action = 0;
    CHECK(sj_clean_mask() == 0 && raise(SIGUSR1) == 0 && pj_seen == 2);
    if (pj_child) _exit(37);
    int status;
    if (fork_handler) CHECK(waitpid(pj_descendant, &status, 0) == pj_descendant
        && WIFEXITED(status) && WEXITSTATUS(status) == 37);
    if (sender >= 0) CHECK(waitpid(sender, &status, 0) == sender
        && WIFEXITED(status) && WEXITSTATUS(status) == 37);
    if (alternate) { stack.ss_flags = SS_DISABLE; CHECK(sigaltstack(&stack, NULL) == 0); }
    printf("plain-jump: entry=%d async=%d alternate=%d fork=%d PASS\n", pj_entry, asynchronous, alternate, fork_handler);
    return 0;
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--after-exec")) return sigjump_regression_main(argc, argv);
    CHECK(pj_values_and_sync() == 0);
    sj_ready = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(sj_ready != MAP_FAILED);
    for (pj_entry = 0; pj_entry < 4; ++pj_entry)
        for (int asynchronous = 0; asynchronous < 2; ++asynchronous)
            for (int alternate = 0; alternate < 2; ++alternate)
                for (int fork_handler = 0; fork_handler < 2; ++fork_handler)
                    CHECK(pj_native_or_fork(asynchronous, alternate, fork_handler) == 0);
    CHECK(munmap((void *)sj_ready, 4096) == 0);
    CHECK(sigjump_regression_main(argc, argv) == 0);
    puts("plain-jump: PASS unified plain/signal jump runtime and full signal regressions");
    return 0;
}
