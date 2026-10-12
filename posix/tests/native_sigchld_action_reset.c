#define _GNU_SOURCE 1
/* Isolated Compositor-slot KVM probe; no desktop readiness is published. */
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static _Atomic unsigned notifications;
static unsigned iteration;

static void debug(const char *message) {
    uint64_t number = 660;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"((uintptr_t)message), "S"((uint64_t)strlen(message))
                     : "rcx", "r11", "memory");
}

#define CHECK(condition) do { if (!(condition)) { \
    char message[160]; \
    snprintf(message, sizeof(message), "native-sigchld-reset: FAIL iteration=%u line=%u errno=%d notifications=%u\n", \
             iteration, __LINE__, errno, atomic_load(&notifications)); \
    debug(message); return 1; \
} } while (0)

static void on_child(int signal_number) {
    if (signal_number == SIGCHLD) atomic_fetch_add(&notifications, 1);
}

static int pause_briefly(void) {
    struct timespec delay = {0, 1000000};
    return nanosleep(&delay, NULL) == 0 || errno == EINTR;
}

static int await_reaped(pid_t child) {
    for (unsigned retry = 0; retry < 2000; ++retry) {
        if (getpgid(child) == -1) return errno == ESRCH;
        if (!pause_briefly()) return 0;
    }
    return 0;
}

int main(void) {
    struct sigaction action = {0};
    sigset_t blocked, original, pending;
    CHECK(sigemptyset(&action.sa_mask) == 0);
    action.sa_handler = on_child;
    CHECK(sigaction(SIGCHLD, &action, NULL) == 0);
    CHECK(sigemptyset(&blocked) == 0 && sigaddset(&blocked, SIGCHLD) == 0);
    CHECK(sigprocmask(SIG_BLOCK, &blocked, &original) == 0);
    CHECK(raise(SIGCHLD) == 0);
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGCHLD) == 1);
    action.sa_handler = SIG_DFL;
    CHECK(sigaction(SIGCHLD, &action, NULL) == 0);
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGCHLD) == 0);
    action.sa_handler = on_child;
    CHECK(sigaction(SIGCHLD, &action, NULL) == 0);
    CHECK(sigprocmask(SIG_SETMASK, &original, NULL) == 0);
    CHECK(atomic_load(&notifications) == 0);
    debug("native-sigchld-reset: blocked notification discarded on SIG_DFL\n");

    for (iteration = 0; iteration < 32; ++iteration) {
        action.sa_handler = SIG_IGN;
        action.sa_flags = 0;
        CHECK(sigaction(SIGCHLD, &action, NULL) == 0);
        pid_t child = fork();
        CHECK(child >= 0);
        if (child == 0) _exit(7);
        CHECK(await_reaped(child));
        int status = 99;
        CHECK(waitpid(child, &status, 0) == -1 && errno == ECHILD && status == 99);

        action.sa_handler = SIG_DFL;
        CHECK(sigaction(SIGCHLD, &action, NULL) == 0);
        child = fork();
        CHECK(child >= 0);
        if (child == 0) _exit(8);
        CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 8);
        CHECK(raise(SIGCONT) == 0);

        unsigned before = atomic_load(&notifications);
        action.sa_handler = on_child;
        action.sa_flags = SA_NOCLDWAIT | SA_RESTART;
        CHECK(sigaction(SIGCHLD, &action, NULL) == 0);
        child = fork();
        CHECK(child >= 0);
        if (child == 0) _exit(9);
        CHECK(await_reaped(child));
        for (unsigned retry = 0; retry < 2000 && atomic_load(&notifications) == before; ++retry)
            CHECK(pause_briefly());
        CHECK(atomic_load(&notifications) == before + 1);
        CHECK(waitpid(child, &status, 0) == -1 && errno == ECHILD);
    }
    debug("native-sigchld-reset: PASS 32 ignore/default/SA_NOCLDWAIT transitions\n");
    return 0;
}
