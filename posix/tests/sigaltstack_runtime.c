#define SIGINFO_TEST_ENTRY siginfo_regression_main
#include "sa_siginfo_runtime.c"
#undef SIGINFO_TEST_ENTRY
#undef CHECK
#include <pthread.h>

#define CHECK(test) do { if (!(test)) { fprintf(stderr, "sigaltstack: FAIL line=%d errno=%d\n", __LINE__, errno); return 1; } } while (0)
static uintptr_t alt_base, alt_size;
static volatile uintptr_t alt_outer;
static volatile sig_atomic_t alt_error, alt_calls, alt_nested, alt_faults, alt_minimal;

static int inside(uintptr_t pointer) {
    return pointer >= alt_base && pointer - alt_base < alt_size;
}
static void inspect_stack(uintptr_t pointer) {
    stack_t observed, disabled = {.ss_flags = SS_DISABLE};
    if (!inside(pointer) || sigaltstack(NULL, &observed) || observed.ss_flags != SS_ONSTACK
        || (uintptr_t)observed.ss_sp != alt_base || observed.ss_size != alt_size) alt_error = 1;
    if (sigaltstack(&disabled, NULL) != -1 || errno != EPERM) alt_error = 2;
}
static void nested_alt(int signal) {
    volatile uint64_t local = 0;
    inspect_stack((uintptr_t)&local);
    if (signal != SIGUSR2 || (uintptr_t)&local >= alt_outer) alt_error = 3;
    ++alt_nested;
}
static void alternate(int signal, siginfo_t *info, void *raw) {
    volatile uint64_t canary = UINT64_C(0x123456789abcdef0);
    ucontext_t *context = raw;
    inspect_stack((uintptr_t)&canary);
    if (!context || !info || (uintptr_t)context->uc_stack.ss_sp != alt_base
        || context->uc_stack.ss_size != alt_size || context->uc_stack.ss_flags != 0) alt_error = 4;
    if (signal == SIGUSR1) {
        alt_outer = (uintptr_t)&canary;
        if (raise(SIGUSR2)) alt_error = 5;
        if (canary != UINT64_C(0x123456789abcdef0)) alt_error = 6;
        ++alt_calls;
    } else if (signal == SIGSEGV) {
        if (info->si_addr != NULL || info->si_code != SEGV_MAPERR) alt_error = 7;
        context->uc_mcontext.gregs[REG_RIP] = (uintptr_t)siginfo_fault_resume;
        context->uc_mcontext.gregs[REG_RAX] = 55;
        ++alt_faults;
    } else alt_error = 8;
    errno = 99;
}
static void minimal(int signal) {
    volatile unsigned local = 0;
    if (signal != SIGUSR1 || !inside((uintptr_t)&local)) alt_error = 9;
    ++alt_minimal;
}
static void *new_thread(void *argument) {
    (void)argument;
    stack_t observed;
    return (void *)(uintptr_t)(sigaltstack(NULL, &observed) || observed.ss_flags != SS_DISABLE);
}
static void *guarded_stack(size_t size, size_t page, size_t *mapping_size) {
    size_t extent = ((size + page - 1) / page) * page;
    *mapping_size = extent + 2 * page;
    unsigned char *mapping = mmap(NULL, *mapping_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) return MAP_FAILED;
    if (mprotect(mapping + page, extent, PROT_READ | PROT_WRITE)) return MAP_FAILED;
    alt_base = (uintptr_t)(mapping + page);
    alt_size = size;
    return mapping;
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--after-exec")) {
        stack_t state;
        return sigaltstack(NULL, &state) == 0 && state.ss_flags == SS_DISABLE ? 37 : 97;
    }
    CHECK(siginfo_regression_main() == 0);
    puts("sigaltstack: start");
    struct sigaction default_child = {0};
    CHECK(sigaction(SIGCHLD, &default_child, NULL) == 0);
    stack_t observed;
    CHECK(sigaltstack(NULL, &observed) == 0 && observed.ss_flags == SS_DISABLE);
    size_t page = (size_t)sysconf(_SC_PAGESIZE), mapping_size;
    void *mapping = guarded_stack(SIGSTKSZ * 4, page, &mapping_size);
    CHECK(mapping != MAP_FAILED);
    stack_t configuration = {.ss_sp = (void *)alt_base, .ss_size = alt_size};
    stack_t invalid = configuration;
    invalid.ss_size = MINSIGSTKSZ - 1;
    CHECK(sigaltstack(&invalid, NULL) == -1 && errno == ENOMEM);
    invalid = configuration; invalid.ss_flags = SS_ONSTACK;
    CHECK(sigaltstack(&invalid, NULL) == -1 && errno == EINVAL);
    CHECK(sigaltstack(&configuration, &observed) == 0 && observed.ss_flags == SS_DISABLE);
    CHECK(sigaltstack(NULL, &observed) == 0 && observed.ss_flags == 0 && observed.ss_sp == configuration.ss_sp);
    struct sigaction action = {0};
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    action.sa_sigaction = alternate;
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0 && sigaction(SIGSEGV, &action, NULL) == 0);
    action.sa_flags = 0; action.sa_handler = nested_alt;
    CHECK(sigaction(SIGUSR2, &action, NULL) == 0);
    errno = 42;
    CHECK(raise(SIGUSR1) == 0 && alt_calls == 1 && alt_nested == 1 && !alt_error && errno == 42);
    CHECK(siginfo_fault() == 55 && alt_faults == 1 && !alt_error);
    puts("sigaltstack: nested handlers and fault return");
    pthread_t thread;
    void *result;
    CHECK(pthread_create(&thread, NULL, new_thread, NULL) == 0);
    CHECK(pthread_join(thread, &result) == 0 && result == NULL);
    CHECK(sigaltstack(NULL, &observed) == 0 && observed.ss_sp == configuration.ss_sp);
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        stack_t inherited;
        if (sigaltstack(NULL, &inherited) || inherited.ss_sp != configuration.ss_sp || inherited.ss_size != configuration.ss_size
            || inherited.ss_flags || raise(SIGUSR1) || alt_error) _exit(96);
        _exit(37);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 37);
    child = fork(); CHECK(child >= 0);
    if (!child) {
        char *arguments[] = {"altstack", "--after-exec", NULL};
        char *environment[] = {NULL};
        execve("/system/services/compositor.service", arguments, environment);
        _exit(95);
    }
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 37);
    puts("sigaltstack: pthread isolation, fork inheritance and exec reset");
    stack_t disabled = {.ss_flags = SS_DISABLE};
    CHECK(sigaltstack(&disabled, NULL) == 0 && munmap(mapping, mapping_size) == 0);
    mapping = guarded_stack(MINSIGSTKSZ, page, &mapping_size);
    CHECK(mapping != MAP_FAILED);
    configuration.ss_sp = (void *)alt_base; configuration.ss_size = alt_size;
    CHECK(sigaltstack(&configuration, NULL) == 0);
    action.sa_flags = SA_ONSTACK; action.sa_handler = minimal;
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    CHECK(raise(SIGUSR1) == 0 && alt_minimal == 1 && !alt_error);
    CHECK(sigaltstack(&disabled, NULL) == 0 && munmap(mapping, mapping_size) == 0);
    puts("sigaltstack: PASS real/nested stack use, active change rejection, guarded minimum stack, pthread/fork/exec and errno");
    return 0;
}
