/* Isolated Compositor-slot KVM test: real newlib -> HandleControl -> PTY
 * provider and service-owned foreground signal delivery, not a desktop test. */
#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
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
    struct termios attributes;
    CHECK(ioctl(slave, TCGETS, &attributes) == 0);
    CHECK(ioctl(slave, TCSETS, &attributes) == 0);
    CHECK(ioctl(slave, TCSETSW, &attributes) == 0);
    CHECK(ioctl(slave, TCSETSF, &attributes) == 0);
    CHECK(fcntl(master, F_SETFL, O_NONBLOCK) == 0);
    CHECK(tcflow(slave, TCOOFF) == 0);
    CHECK(write(slave, "queued", 6) == 6);
    char flow_bytes[8];
    errno = 0;
    CHECK(read(master, flow_bytes, sizeof(flow_bytes)) == -1 && errno == EAGAIN);
    CHECK(tcflow(slave, TCOON) == 0);
    CHECK(read(master, flow_bytes, sizeof(flow_bytes)) == 6);
    CHECK(memcmp(flow_bytes, "queued", 6) == 0);
    CHECK(tcflow(slave, TCIOFF) == 0);
    CHECK(tcflow(slave, TCION) == 0);
    CHECK(read(master, flow_bytes, sizeof(flow_bytes)) == 2);
    CHECK((unsigned char)flow_bytes[0] == attributes.c_cc[VSTOP]);
    CHECK((unsigned char)flow_bytes[1] == attributes.c_cc[VSTART]);
    errno = 0;
    CHECK(tcflow(slave, -1) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(tcflow(-1, TCOON) == -1 && errno == EBADF);
    CHECK(ioctl(master, TIOCGWINSZ, &actual) == 0);
    CHECK(memcmp(&actual, &initial, sizeof(actual)) == 0);
    errno = 0;
    CHECK(ioctl(master, 0xdeadUL) == -1 && errno == ENOTTY);
    errno = 0;
    CHECK(ioctl(-1, TIOCGWINSZ) == -1 && errno == EBADF);
    errno = 0;
    CHECK(ioctl(master, TIOCGWINSZ, (void *)0) == -1 && errno == EFAULT);
    int pipes[2];
    CHECK(pipe(pipes) == 0);
    errno = 0;
    CHECK(ioctl(pipes[0], TCGETS, &attributes) == -1 && errno == ENOTTY);
    errno = 0;
    CHECK(tcflow(pipes[0], TCOON) == -1 && errno == ENOTTY);
    CHECK(close(pipes[0]) == 0 && close(pipes[1]) == 0);
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
    pid_t foreground = -1;
    CHECK(ioctl(STDIN_FILENO, TIOCGPGRP, &foreground) == 0);
    CHECK(foreground == getpgrp());
    CHECK(ioctl(STDIN_FILENO, TIOCSPGRP, &foreground) == 0);
    struct winsize changed = {42, 132, 1920, 1080};
    CHECK(ioctl(master, TIOCSWINSZ, &changed) == 0);
    CHECK(tcgetwinsize(STDIN_FILENO, &actual) == 0);
    CHECK(memcmp(&actual, &changed, sizeof(actual)) == 0);
    for (unsigned retry = 0; retry < 1000 && resized == 0; ++retry) {
        struct timespec pause = {0, 1000000};
        nanosleep(&pause, NULL);
    }
    CHECK(resized == 1);
    CHECK(ioctl(STDIN_FILENO, TIOCSWINSZ, &changed) == 0);
    for (unsigned retry = 0; retry < 20; ++retry) {
        struct timespec pause = {0, 1000000};
        nanosleep(&pause, NULL);
    }
    CHECK(resized == 1);
    debug("native-terminal-window: PASS ioctl, tcflow, attributes, process group, size, errors and SIGWINCH\n");
    CHECK(close(master) == 0);
    return 0;
}
