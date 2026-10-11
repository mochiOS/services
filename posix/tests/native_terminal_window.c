/* Isolated Compositor-slot KVM test: real newlib -> HandleControl -> PTY
 * provider and service-owned foreground signal delivery, not a desktop test. */
#include <errno.h>
#include <pty.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t resized;
static void on_resize(int signal_number) { if (signal_number == SIGWINCH) ++resized; }

static void debug(const char *message) {
    uint64_t number = 660;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"((uintptr_t)message), "S"((uint64_t)strlen(message))
                     : "rcx", "r11", "memory");
}

#define CHECK(condition) do { \
    if (!(condition)) { \
        char message[128]; \
        snprintf(message, sizeof(message), "native-terminal-window: FAIL line=%u errno=%d\n", \
                 (unsigned)__LINE__, errno); \
        debug(message); return 1; \
    } \
} while (0)

int main(void) {
    struct winsize initial = {24, 80, 640, 480}, actual = {0};
    int master = -1, slave = -1;
    CHECK(openpty(&master, &slave, NULL, NULL, &initial) == 0);
    CHECK(tcgetwinsize(master, &actual) == 0);
    CHECK(memcmp(&actual, &initial, sizeof(actual)) == 0);
    int duplicate = dup(slave);
    CHECK(duplicate >= 0);
    CHECK(tcgetwinsize(duplicate, &actual) == 0);
    CHECK(memcmp(&actual, &initial, sizeof(actual)) == 0);
    CHECK(close(duplicate) == 0);
    errno = 0;
    CHECK(tcgetwinsize(-1, &actual) == -1 && errno == EBADF);
    errno = 0;
    CHECK(tcgetwinsize(master, NULL) == -1 && errno == EFAULT);
    errno = 0;
    CHECK(tcsetwinsize(master, NULL) == -1 && errno == EFAULT);
    struct sigaction action = {0};
    action.sa_handler = on_resize;
    CHECK(sigemptyset(&action.sa_mask) == 0);
    CHECK(sigaction(SIGWINCH, &action, NULL) == 0);
    CHECK(login_tty(slave) == 0);
    struct winsize changed = {42, 132, 1920, 1080};
    CHECK(tcsetwinsize(master, &changed) == 0);
    CHECK(tcgetwinsize(STDIN_FILENO, &actual) == 0);
    CHECK(memcmp(&actual, &changed, sizeof(actual)) == 0);
    for (unsigned retry = 0; retry < 1000 && resized == 0; ++retry) {
        struct timespec pause = {0, 1000000};
        nanosleep(&pause, NULL);
    }
    CHECK(resized == 1);
    CHECK(tcsetwinsize(STDIN_FILENO, &changed) == 0);
    for (unsigned retry = 0; retry < 20; ++retry) {
        struct timespec pause = {0, 1000000};
        nanosleep(&pause, NULL);
    }
    CHECK(resized == 1);
    debug("native-terminal-window: PASS initial size, both PTY sides, dup, errors and foreground SIGWINCH\n");
    CHECK(close(master) == 0);
    return 0;
}
