#define main legacy_memory_fault_main
#include "posix_memory_fault.c"
#undef main
#include <ucontext.h>
#include <string.h>
#include <time.h>
#include <sched.h>

#define CHECK(test) do { if (!(test)) { fprintf(stderr, "sa-siginfo: FAIL line=%d errno=%d\n", __LINE__, errno); return 1; } } while (0)
static volatile sig_atomic_t info_counts[32], info_error, mode;
static volatile pid_t expected_sender;
static volatile uintptr_t expected_address;
extern long siginfo_fault(void);
extern void siginfo_fault_instruction(void), siginfo_fault_resume(void);
__asm__(".text\n.globl siginfo_fault\n.type siginfo_fault,@function\n"
        "siginfo_fault:\n xor %eax,%eax\n"
        ".globl siginfo_fault_instruction\nsiginfo_fault_instruction:\n mov (%rax),%rax\n"
        ".globl siginfo_fault_resume\nsiginfo_fault_resume:\n ret\n"
        ".size siginfo_fault,.-siginfo_fault\n");

static void info_handler(int signal, siginfo_t *info, void *raw_context) {
    ucontext_t *context = raw_context;
    if (!info || !context || info->si_signo != signal || !context->uc_mcontext.gregs[REG_RIP]
        || !context->uc_mcontext.gregs[REG_RSP] || context->uc_stack.ss_flags != SS_DISABLE) {
        info_error = 1; return;
    }
    ++info_counts[signal];
    if (signal == SIGSEGV && mode == 3) {
        if (info->si_code != SEGV_MAPERR || info->si_addr != NULL
            || context->uc_mcontext.gregs[REG_RIP] != (uintptr_t)siginfo_fault_instruction) info_error = 2;
        context->uc_mcontext.gregs[REG_RIP] = (uintptr_t)siginfo_fault_resume;
        context->uc_mcontext.gregs[REG_RAX] = 37;
    } else if (signal == SIGCHLD) {
        if (info->si_code != CLD_EXITED || info->si_pid != expected_sender || info->si_status != 37) info_error = 3;
    } else if (signal == SIGBUS) {
        if (info->si_code != BUS_ADRERR || info->si_addr != (void *)expected_address) info_error = 4;
        if (native(MEMORY_RESIZE, repair_object, 8192, 0, 0, 0, 0)) _exit(93);
    } else {
        if (info->si_code != SI_USER || info->si_pid != expected_sender || info->si_uid != getuid()
            || info->si_addr != NULL) info_error = 5;
        sigset_t inside;
        if (sigprocmask(SIG_SETMASK, NULL, &inside) || !sigismember(&inside, signal)
            || sigismember(&context->uc_sigmask, signal)) info_error = 6;
        if (signal == SIGUSR1 && mode == 1) sigaddset(&context->uc_sigmask, SIGUSR2);
        if (signal == SIGUSR1 && mode == 2 && raise(SIGUSR2)) info_error = 7;
    }
    errno = 99;
}

int main(void) {
    CHECK(legacy_memory_fault_main() == 0);
    sigset_t old_children;
    sigemptyset(&old_children); sigaddset(&old_children, SIGCHLD);
    CHECK(sigprocmask(SIG_BLOCK, &old_children, NULL) == 0);
    struct timespec poll_timeout = {0};
    while (sigtimedwait(&old_children, NULL, &poll_timeout) == SIGCHLD) {}
    CHECK(errno == EAGAIN);
    puts("sa-siginfo: actions");
    struct sigaction action = {0}, observed;
    action.sa_sigaction = info_handler;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    for (unsigned i = 0; i < 5; ++i) {
        int signals[] = {SIGUSR1,SIGUSR2,SIGSEGV,SIGBUS,SIGCHLD};
        CHECK(sigaction(signals[i], &action, NULL) == 0);
    }
    CHECK(sigaction(SIGUSR1, NULL, &observed) == 0 && observed.sa_sigaction == info_handler && observed.sa_flags == SA_SIGINFO);
    expected_sender = getpid();
    mode = 1;
    errno = 42;
    CHECK(raise(SIGUSR1) == 0 && info_counts[SIGUSR1] == 1 && !info_error && errno == 42);
    sigset_t mask;
    CHECK(sigprocmask(SIG_SETMASK, NULL, &mask) == 0 && sigismember(&mask, SIGUSR2));
    puts("sa-siginfo: self delivery and mask edit");
    sigemptyset(&mask);
    CHECK(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);
    mode = 2;
    CHECK(raise(SIGUSR1) == 0 && info_counts[SIGUSR1] == 2 && info_counts[SIGUSR2] == 1 && !info_error);
    puts("sa-siginfo: nested delivery");
    mode = 0;
    CHECK(raise(SIGSEGV) == 0 && info_counts[SIGSEGV] == 1 && !info_error);
    mode = 3;
    errno = 42;
    CHECK(siginfo_fault() == 37 && info_counts[SIGSEGV] == 2 && !info_error && errno == 42);
    uint64_t object;
    uint64_t memory = outside_backing(0, &object);
    CHECK(memory != 0);
    expected_address = memory;
    repair_object = object;
    CHECK(*(volatile unsigned char *)(uintptr_t)memory == 0 && info_counts[SIGBUS] == 1 && !info_error);
    CHECK(native(MEMORY_UNMAP, memory, 4096, 0, 0, 0, 0) == 0);
    CHECK(native(HANDLE_CLOSE, object, 0, 0, 0, 0, 0) == 0);
    sigemptyset(&mask); sigaddset(&mask, SIGCHLD);
    CHECK(sigprocmask(SIG_BLOCK, &mask, NULL) == 0);
    pid_t parent = getpid();
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        struct timespec delay = {0, 20000000};
        if (nanosleep(&delay, NULL) || kill(parent, SIGUSR1)) _exit(98);
        _exit(37);
    }
    expected_sender = child;
    mode = 0;
    struct timespec started, now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &started) == 0);
    while (info_counts[SIGUSR1] != 3) {
        CHECK(sched_yield() == 0 && clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        CHECK((now.tv_sec - started.tv_sec) * INT64_C(1000000000) + now.tv_nsec - started.tv_nsec < INT64_C(2000000000));
    }
    CHECK(!info_error);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 37);
    CHECK(sigprocmask(SIG_UNBLOCK, &mask, NULL) == 0 && info_counts[SIGCHLD] == 1 && !info_error);
    puts("sa-siginfo: PASS external/self/child/fault metadata, real contexts, nested raise, mask edits, errno and fault PC/register return");
    return 0;
}
