#define ALTSTACK_TEST_ENTRY altstack_regression_main
#include "sigaltstack_runtime.c"
#undef ALTSTACK_TEST_ENTRY
#undef CHECK
#define CHECK(test) do { if (!(test)) { fprintf(stderr, "signal-fork: FAIL line=%d errno=%d\n", __LINE__, errno); return 1; } } while (0)

static volatile sig_atomic_t fork_seen, fork_error, fork_child, fork_mode, fork_async;
static volatile pid_t fork_descendant;
static volatile unsigned *fork_ready;
extern char signal_fork_spin_begin[], signal_fork_spin_end[];

static void perform_fork(void) {
    unsigned attempts = fork_mode == 4 ? 1 : 2;
    for (unsigned attempt = 0; attempt < attempts; ++attempt) {
        pid_t child = fork();
        if (child < 0) { fork_error = 1; return; }
        fork_descendant = child;
        if (child) return;
        fork_child = 1;
    }
}
static void fork_handler(int signal, siginfo_t *info, void *raw) {
    ucontext_t *context = raw;
    if (!context || !info) { fork_error = 2; return; }
    if (signal == SIGSEGV) {
        perform_fork();
        context->uc_mcontext.gregs[REG_RIP] = (uintptr_t)siginfo_fault_resume;
        context->uc_mcontext.gregs[REG_RAX] = 61;
    } else if (signal == SIGUSR2) {
        perform_fork();
    } else if (signal == SIGUSR1) {
        if (fork_async) {
            static const char marker[] = "signal-fork: async handler entered\n";
            (void)write(2, marker, sizeof(marker) - 1);
        }
        uintptr_t instruction = context->uc_mcontext.gregs[REG_RIP];
        if (fork_async && (instruction < (uintptr_t)signal_fork_spin_begin
            || instruction >= (uintptr_t)signal_fork_spin_end)) fork_error = 3;
        if (fork_mode == 2) {
            if (raise(SIGUSR2)) fork_error = 4;
        } else {
            perform_fork();
            /* In the fork child, exercise delivery while the copied outer
               native callback is still live, including a second fork there. */
            if (fork_mode == 4 && fork_child && raise(SIGUSR2)) fork_error = 7;
        }
        fork_seen = 1;
    } else fork_error = 5;
}
static void after_fork_signal(int signal) {
    if (signal != SIGUSR2) fork_error = 6;
    ++fork_seen;
}
static int check_child(void) {
    sigset_t mask;
    stack_t stack;
    if (fork_error || sigprocmask(SIG_SETMASK, NULL, &mask)
        || sigismember(&mask, SIGUSR1) || sigismember(&mask, SIGUSR2)
        || sigismember(&mask, SIGSEGV) || sigaltstack(NULL, &stack)
        || stack.ss_flags == SS_ONSTACK) return 92;
    if (fork_descendant > 0) {
        int status;
        if (waitpid(fork_descendant, &status, 0) != fork_descendant
            || !WIFEXITED(status) || WEXITSTATUS(status) != 37) return 93;
    }
    struct sigaction action = {0};
    action.sa_handler = after_fork_signal;
    if (sigaction(SIGUSR2, &action, NULL)) return 94;
    int before = fork_seen;
    if (raise(SIGUSR2) || fork_seen != before + 1 || fork_error) return 95;
    return 37;
}
static int signal_case(int mode, int asynchronous) {
    fork_seen = fork_error = fork_child = fork_descendant = 0;
    fork_mode = mode; fork_async = asynchronous;
    fprintf(stderr, "signal-fork: begin mode=%d async=%d\n", mode, asynchronous);
    struct sigaction action = {0};
    action.sa_flags = SA_SIGINFO | (mode ? SA_ONSTACK : 0);
    action.sa_sigaction = fork_handler;
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    CHECK(sigaction(SIGUSR2, &action, NULL) == 0);
    CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
    pid_t sender = -1;
    if (mode == 3) {
        CHECK(siginfo_fault() == 61);
    } else if (asynchronous) {
        *fork_ready = 0;
        pid_t parent = getpid();
        sender = fork(); CHECK(sender >= 0);
        if (!sender) {
            fprintf(stderr, "signal-fork: sender waiting for busy loop\n");
            while (!*fork_ready) __asm__ volatile("pause");
            fprintf(stderr, "signal-fork: sender delivering\n");
            if (kill(parent, SIGUSR1)) _exit(96);
            _exit(37);
        }
        /* No libc checkpoint is executed in this loop. The sender waits until
           the parent has entered the labelled range before delivering. */
        __asm__ volatile(
            ".global signal_fork_spin_begin\nsignal_fork_spin_begin:\n"
            "movl $1,(%0)\n1: pause\ncmpl $0,(%1)\nje 1b\n"
            ".global signal_fork_spin_end\nsignal_fork_spin_end:\n"
            : : "r"(fork_ready), "r"(&fork_seen) : "memory", "cc");
    } else {
        CHECK(raise(SIGUSR1) == 0);
    }
    if (fork_child) _exit(check_child());
    CHECK(!fork_error && fork_descendant > 0);
    int status;
    CHECK(waitpid(fork_descendant, &status, 0) == fork_descendant
        && WIFEXITED(status) && WEXITSTATUS(status) == 37);
    if (sender > 0) CHECK(waitpid(sender, &status, 0) == sender
        && WIFEXITED(status) && WEXITSTATUS(status) == 37);
    printf("signal-fork: mode=%d async=%d PASS\n", mode, asynchronous);
    return 0;
}
int main(int argc, char **argv) {
    /* The included regression execs this same image for altstack reset. */
    if (argc == 2 && !strcmp(argv[1], "--after-exec"))
        return altstack_regression_main(argc, argv);
    CHECK(altstack_regression_main(argc, argv) == 0);
    fork_ready = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(fork_ready != MAP_FAILED);
    /* Fork copies descriptor tables and native creation metadata. Provision
       stack space for that workload; the included regression separately
       checks a bare handler on guarded MINSIGSTKSZ storage. */
    size_t stack_mapping_size;
    void *memory = guarded_stack(SIGSTKSZ * 32, (size_t)sysconf(_SC_PAGESIZE), &stack_mapping_size);
    CHECK(memory != MAP_FAILED);
    stack_t stack = {.ss_sp = (void *)alt_base, .ss_size = alt_size};
    CHECK(sigaltstack(&stack, NULL) == 0);
    for (int mode = 0; mode < 3; ++mode) {
        CHECK(signal_case(mode, 0) == 0);
        CHECK(signal_case(mode, 1) == 0);
    }
    CHECK(signal_case(3, 0) == 0);
    CHECK(signal_case(4, 0) == 0);
    CHECK(signal_case(4, 1) == 0);
    stack.ss_flags = SS_DISABLE;
    CHECK(sigaltstack(&stack, NULL) == 0);
    CHECK(munmap(memory, stack_mapping_size) == 0 && munmap((void *)fork_ready, 4096) == 0);
    puts("signal-fork: PASS repeated handler forks, async busy-loop return, nested handlers, alternate stacks, fault repair, fresh child delivery and masks");
    return 0;
}
