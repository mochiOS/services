/* Isolated Compositor-slot KVM probe, using its existing spawn capability.
 * A separate test readiness gate replaces Input; neither is a desktop test. */
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <signal.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "failed-spawn-cleanup: FAIL line %d errno %d\n", __LINE__, errno); \
        return 1; \
    } \
} while (0)

static void caught_signal(int signal_number) {
    (void)signal_number;
}

/* Direct client/service boundary probe. The wire payload contains no TID or
 * PID; posix.service must obtain both from the native request endpoint. */
static int service_mask(uint32_t operation, uint64_t mask, uint64_t *previous) {
    struct {
        char magic[4]; uint16_t version, opcode;
        uint64_t request_id;
        uint32_t flags, length; int32_t status; uint32_t reserved;
        uint32_t operation, mask_reserved; uint64_t mask;
    } request = {{'P', 'O', 'S', 'X'}, 1, 65, 1, 0, 16, 0, 0, operation, 0, mask};
    unsigned char reply[40] = {0};
    _Static_assert(sizeof(request) == 48, "POSIX mask wire layout");
    uint64_t endpoint = UINT64_C(0x4c52544358534f50);
    uint64_t number = 628;
    __asm__ volatile("syscall" : "+a"(number) : "D"(endpoint) : "rcx", "r11", "memory");
    if (number == 0 || number >= UINT64_MAX - 4094) return 1;
    endpoint = number;
    number = 588;
    register uint64_t r10 __asm__("r10") = (uintptr_t)reply;
    register uint64_t r8 __asm__("r8") = sizeof(reply);
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(endpoint), "S"(&request), "d"(sizeof(request)), "r"(r10), "r"(r8)
                     : "rcx", "r11", "memory");
    int32_t status;
    memcpy(&status, reply + 24, sizeof(status));
    if (number >= UINT64_MAX - 4094 || (uint32_t)number != sizeof(reply) ||
        memcmp(reply, "POSX", 4) != 0 || status != 0) return 2;
    memcpy(previous, reply + 32, sizeof(*previous));
    return 0;
}

static void *inspect_service_thread_mask(void *unused) {
    (void)unused;
    uint64_t previous;
    if (service_mask(0, 0, &previous) || previous != 0 ||
        service_mask(1, UINT64_C(1) << 30, &previous) || previous != 0 ||
        service_mask(0, 0, &previous) || previous != (UINT64_C(1) << 30))
        return (void *)1;
    return NULL;
}

static int inspect_service_masks(void) {
    uint64_t previous;
    uint64_t first = UINT64_C(1) << 29;
    uint64_t unblockable = (UINT64_C(1) << (SIGKILL - 1)) | (UINT64_C(1) << (SIGSTOP - 1));
    CHECK(service_mask(4, first, &previous) == 0 && previous == first);
    CHECK(service_mask(2, unblockable, &previous) == 0 && previous == first);
    CHECK(service_mask(4, 0, &previous) == 0 && previous == first);
    pthread_t thread;
    void *result = (void *)1;
    CHECK(pthread_create(&thread, NULL, inspect_service_thread_mask, NULL) == 0);
    CHECK(pthread_join(thread, &result) == 0 && result == NULL);
    CHECK(service_mask(0, 0, &previous) == 0 && previous == first);
    CHECK(service_mask(3, first, &previous) == 0 && previous == first);
    CHECK(service_mask(0, 0, &previous) == 0 && previous == 0);
    fprintf(stderr, "native-signal-masks: PASS authenticated per-thread masks, initialize preservation and unblockable signals\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && (strcmp(argv[1], "--exec-child") == 0 ||
                     strcmp(argv[1], "--exec-default-child") == 0)) {
        int preserve_ignore = strcmp(argv[1], "--exec-child") == 0;
        struct sigaction inherited;
        if (sigaction(SIGUSR1, NULL, &inherited) != 0 ||
            inherited.sa_handler != (preserve_ignore ? SIG_IGN : SIG_DFL) ||
            sigaction(SIGUSR2, NULL, &inherited) != 0 || inherited.sa_handler != SIG_DFL ||
            (preserve_ignore && kill(getpid(), SIGUSR1) != 0)) _exit(97);
        int closed_flags = fcntl(5, F_GETFD);
        int closed_error = errno;
        int inherited_flags = fcntl(9, F_GETFD);
        const char *environment = getenv("POSIX_EXEC_PROBE");
        fprintf(stderr, "native-exec: child argv0=%s fd5=%d errno=%d fd9=%d env=%s\n",
                argv[0], closed_flags, closed_error, inherited_flags,
                environment == NULL ? "<missing>" : environment);
        errno = 0;
        if (strcmp(argv[0], "explicit-argv-zero") != 0 ||
            fcntl(5, F_GETFD) != -1 || errno != EBADF ||
            fcntl(9, F_GETFD) != 0 || getenv("POSIX_EXEC_PROBE") == NULL ||
            strcmp(getenv("POSIX_EXEC_PROBE"), "inherited") != 0)
            _exit(91);
        pid_t nested = fork();
        if (nested < 0) _exit(95);
        if (nested == 0) _exit(43);
        int nested_status = 0;
        if (waitpid(nested, &nested_status, 0) != nested ||
            !WIFEXITED(nested_status) || WEXITSTATUS(nested_status) != 43)
            _exit(96);
        const unsigned char marker = 0x41;
        if (write(9, &marker, 1) != 1 || close(9) != 0) _exit(92);
        _exit(41);
    }
    fprintf(stderr, "failed-spawn-cleanup: start\n");
    CHECK(inspect_service_masks() == 0);
    posix_spawn_file_actions_t actions;
    CHECK(posix_spawn_file_actions_init(&actions) == 0);
    /* FD 63 is in range but unopened. Failure occurs in the registered child,
     * not during parent-side argument validation or ELF authorization. */
    CHECK(posix_spawn_file_actions_adddup2(&actions, 63, 5) == 0);
    char *arguments[] = {"failed-spawn-child", NULL};
    char *environment[] = {NULL};
    for (unsigned attempt = 0; attempt < 4; ++attempt) {
        pid_t child = -99;
        int error = posix_spawn(&child, "/system/services/compositor.service",
                                &actions, NULL, arguments, environment);
        CHECK(error == EBADF);
        CHECK(child == -99);
        int status = 0;
        errno = 0;
        CHECK(waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD);
    }
    CHECK(posix_spawn_file_actions_destroy(&actions) == 0);
    fprintf(stderr, "failed-spawn-cleanup: PASS repeated child-side failure leaves no waitable child\n");
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) _exit(37);
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 37);
    fprintf(stderr, "failed-spawn-cleanup: PASS successful fork and wait remain usable\n");
    char *exec_arguments[] = {"explicit-argv-zero", "--exec-child", NULL};
    char *exec_environment[] = {"POSIX_EXEC_PROBE=inherited", NULL};
    sigset_t mask, pending;
    fprintf(stderr, "native-signals: blocking SIGUSR1\n");
    CHECK(sigemptyset(&mask) == 0 && sigaddset(&mask, SIGUSR1) == 0);
    CHECK(sigprocmask(SIG_BLOCK, &mask, NULL) == 0);
    fprintf(stderr, "native-signals: sending blocked SIGUSR1\n");
    CHECK(kill(getpid(), SIGUSR1) == 0);
    fprintf(stderr, "native-signals: reading pending SIGUSR1\n");
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGUSR1) == 1);
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_IGN;
    fprintf(stderr, "native-signals: installing SIG_IGN\n");
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    fprintf(stderr, "native-signals: reading discarded SIGUSR1\n");
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGUSR1) == 0);
    CHECK(sigprocmask(SIG_UNBLOCK, &mask, NULL) == 0);
    action.sa_handler = caught_signal;
    CHECK(sigaction(SIGUSR2, &action, NULL) == 0);
    CHECK(execve("/system/services/missing-exec-probe", exec_arguments, exec_environment) == -1);
    CHECK(sigaction(SIGUSR2, NULL, &action) == 0 && action.sa_handler == caught_signal);
    CHECK(sigaction(SIGUSR1, NULL, &action) == 0 && action.sa_handler == SIG_IGN);
    fprintf(stderr, "native-signals: PASS SIG_IGN discards pending signals and failed exec preserves dispositions\n");
    for (unsigned attempt = 0; attempt < 6; ++attempt) {
        int channel[2];
        CHECK(pipe(channel) == 0);
        int cloexec = dup(channel[1]);
        CHECK(cloexec == 5);
        CHECK(fcntl(cloexec, F_SETFD, FD_CLOEXEC) == 0);
        if (attempt < 2 || attempt >= 4) {
            posix_spawnattr_t attributes;
            posix_spawnattr_t *attribute_pointer = NULL;
            if (attempt >= 4) {
                CHECK(posix_spawnattr_init(&attributes) == 0);
                CHECK(posix_spawnattr_setsigdefault(&attributes, &mask) == 0);
                CHECK(posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETSIGDEF) == 0);
                attribute_pointer = &attributes;
                exec_arguments[1] = "--exec-default-child";
            }
            CHECK(posix_spawn_file_actions_init(&actions) == 0);
            CHECK(posix_spawn_file_actions_adddup2(&actions, channel[1], 9) == 0);
            CHECK(posix_spawn_file_actions_addclose(&actions, channel[0]) == 0);
            CHECK(posix_spawn_file_actions_addclose(&actions, channel[1]) == 0);
            CHECK(posix_spawn(&child, "/system/services/compositor.service", &actions,
                              attribute_pointer, exec_arguments, exec_environment) == 0);
            CHECK(posix_spawn_file_actions_destroy(&actions) == 0);
            if (attribute_pointer != NULL) CHECK(posix_spawnattr_destroy(&attributes) == 0);
        } else {
            child = fork();
            CHECK(child >= 0);
            if (child == 0) {
                if (dup2(channel[1], 9) != 9 || close(channel[0]) != 0 ||
                    close(channel[1]) != 0) _exit(93);
                execve("/system/services/compositor.service", exec_arguments, exec_environment);
                fprintf(stderr, "native-exec: execve failed errno %d\n", errno);
                _exit(94);
            }
        }
        CHECK(close(channel[1]) == 0 && close(cloexec) == 0);
        unsigned char marker = 0;
        ssize_t received = read(channel[0], &marker, 1);
        CHECK(waitpid(child, &status, 0) == child);
        fprintf(stderr, "native-exec: attempt=%u read=%d marker=%u status=%d\n",
                attempt, (int)received, marker, status);
        CHECK(received == 1 && marker == 0x41);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 41);
        CHECK(read(channel[0], &marker, 1) == 0 && close(channel[0]) == 0);
    }
    fprintf(stderr, "native-exec: PASS posix_spawn and fork/execve preserve argv/env/non-CLOEXEC FDs, close CLOEXEC FDs and support fork after exec\n");
    fprintf(stderr, "native-signals: PASS spawn and fork/exec preserve SIG_IGN and reset caught dispositions\n");
    fprintf(stderr, "native-signals: PASS POSIX_SPAWN_SETSIGDEF overrides inherited SIG_IGN\n");
    return 0;
}
