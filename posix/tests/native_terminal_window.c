/* Isolated Compositor-slot KVM test: real newlib -> HandleControl -> PTY
 * provider and service-owned foreground signal delivery, not a desktop test. */
#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t resized;
static volatile sig_atomic_t background_stopped;
static volatile sig_atomic_t background_read;
static _Atomic sig_atomic_t waited_signal;
static void on_wait_signal(int signal_number) { if (signal_number == SIGUSR1) ++waited_signal; }
static void on_resize(int signal_number) { if (signal_number == SIGWINCH) ++resized; }
static void on_background(int signal_number) {
    if (signal_number == SIGTTOU) ++background_stopped;
    if (signal_number == SIGTTIN) ++background_read;
}

static int await_ttou(sig_atomic_t expected) {
    for (unsigned retry = 0; retry < 1000 && background_stopped < expected; ++retry) {
        struct timespec pause = {0, 1000000};
        nanosleep(&pause, NULL);
    }
    return background_stopped == expected;
}

static void debug(const char *message) {
    uint64_t number = 660;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"((uintptr_t)message), "S"((uint64_t)strlen(message))
                     : "rcx", "r11", "memory");
}

struct native_wait_guard { uint64_t address, expected; };
static int64_t guarded_native_wait(const struct native_wait_guard *guard, uint64_t deadline) {
    uint64_t number = 682;
    register uint64_t argument __asm__("r10") = (uintptr_t)guard;
    __asm__ volatile("syscall" : "+a"(number)
        : "D"((uint64_t)0), "S"((uint64_t)0), "d"(deadline), "r"(argument)
        : "rcx", "r11", "memory");
    return (int64_t)number;
}

static void *exercise_foreground_io(void *unused) {
    (void)unused;
    for (unsigned iteration = 0; iteration < 32; ++iteration) {
        struct winsize size = {30, (unsigned short)(100 + iteration), 0, 0};
        if (write(STDOUT_FILENO, "x", 1) != 1 || tcsetwinsize(STDIN_FILENO, &size) != 0)
            return (void *)(uintptr_t)1;
    }
    return NULL;
}

static void *read_after_process_stop(void *unused) {
    (void)unused;
    char input[7];
    if (read(STDIN_FILENO, input, sizeof(input)) != 7 || memcmp(input, "resume\n", 7) != 0)
        return (void *)(uintptr_t)1;
    return NULL;
}

static void *interrupt_handle_wait(void *unused) {
    (void)unused;
    sigset_t blocked;
    if (sigemptyset(&blocked) != 0 || sigaddset(&blocked, SIGUSR1) != 0
        || pthread_sigmask(SIG_BLOCK, &blocked, NULL) != 0)
        return (void *)(uintptr_t)1;
    struct timespec pause = {0, 100000000};
    if (nanosleep(&pause, NULL) != 0 || kill(getpid(), SIGUSR1) != 0)
        return (void *)(uintptr_t)1;
    return NULL;
}

static void *complete_restarted_read(void *master_address) {
    if (interrupt_handle_wait(NULL) != NULL) return (void *)(uintptr_t)1;
    for (unsigned retry = 0; retry < 1000 && waited_signal < 2; ++retry) {
        struct timespec pause = {0, 1000000};
        nanosleep(&pause, NULL);
    }
    if (waited_signal != 2 || write(*(int *)master_address, "r\n", 2) != 2)
        return (void *)(uintptr_t)1;
    return NULL;
}

struct stream_wakeup {
    int handle;
    int drain;
    sig_atomic_t observed;
};

static void *interrupt_stream_io(void *context) {
    struct stream_wakeup *wake = context;
    if (interrupt_handle_wait(NULL) != NULL) return (void *)(uintptr_t)1;
    for (unsigned retry = 0; retry < 1000 && waited_signal <= wake->observed; ++retry) {
        struct timespec pause = {0, 1000000};
        nanosleep(&pause, NULL);
    }
    if (waited_signal != wake->observed + 1) return (void *)(uintptr_t)1;
    if (wake->handle >= 0) {
        char byte = 'p';
        ssize_t count = wake->drain ? read(wake->handle, &byte, 1) : write(wake->handle, &byte, 1);
        if (count != 1 || (wake->drain && byte != 'b')) return (void *)(uintptr_t)1;
    }
    return NULL;
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
    _Atomic uint64_t epoch = 9;
    struct native_wait_guard guard = {(uintptr_t)&epoch, 8};
    // A pre-delivered notification must prevent an infinite empty-object wait.
    CHECK(guarded_native_wait(&guard, UINT64_MAX) == -EAGAIN);
    guard.expected = 9;
    CHECK(guarded_native_wait(&guard, 0) == -EAGAIN);
    CHECK(guarded_native_wait(NULL, 0) == -EINVAL);
    guard.address = (uintptr_t)&epoch + 1;
    CHECK(guarded_native_wait(&guard, 0) == -EINVAL);
    guard.address = 0;
    CHECK(guarded_native_wait(&guard, 0) == -EFAULT);
    CHECK(guarded_native_wait((const struct native_wait_guard *)(uintptr_t)(UINT64_MAX - 7), 0) == -EFAULT);
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
    CHECK(tcgetattr(STDIN_FILENO, &attributes) == 0);
    attributes.c_lflag |= TOSTOP;
    CHECK(tcsetattr(STDIN_FILENO, TCSANOW, &attributes) == 0);
    pid_t parent_group = getpgrp();
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        action.sa_handler = on_background;
        CHECK(sigaction(SIGTTOU, &action, NULL) == 0);
        CHECK(sigaction(SIGTTIN, &action, NULL) == 0);
        CHECK(setpgid(0, 0) == 0);
        char byte;
        errno = 0;
        CHECK(read(STDIN_FILENO, &byte, 1) == -1 && errno == EINTR);
        errno = 0;
        CHECK(write(STDOUT_FILENO, "denied", 6) == -1 && errno == EINTR);
        for (unsigned retry = 0; retry < 1000 && (background_read == 0 || background_stopped == 0); ++retry) {
            struct timespec pause = {0, 1000000};
            nanosleep(&pause, NULL);
        }
        CHECK(background_read == 1 && background_stopped == 1);
        // Master control belongs to the terminal controller and is exempt.
        // With TOSTOP clear, slave parameter changes must still signal TTOU.
        CHECK(tcgetattr(master, &attributes) == 0);
        attributes.c_lflag &= ~TOSTOP;
        CHECK(tcsetattr(master, TCSANOW, &attributes) == 0);
        struct termios rejected = attributes, observed;
        rejected.c_lflag ^= ECHO;
        sig_atomic_t expected_ttou = 1;
        const int settings[] = {TCSANOW, TCSADRAIN, TCSAFLUSH};
        for (unsigned index = 0; index < sizeof(settings) / sizeof(settings[0]); ++index) {
            errno = 0;
            CHECK(tcsetattr(STDIN_FILENO, settings[index], &rejected) == -1 && errno == EINTR);
            CHECK(await_ttou(++expected_ttou));
            CHECK(tcgetattr(STDIN_FILENO, &observed) == 0);
            CHECK(observed.c_lflag == attributes.c_lflag);
        }
        errno = 0;
        CHECK(tcdrain(STDIN_FILENO) == -1 && errno == EINTR);
        CHECK(await_ttou(++expected_ttou));
        errno = 0;
        CHECK(tcflush(STDIN_FILENO, TCIOFLUSH) == -1 && errno == EINTR);
        CHECK(await_ttou(++expected_ttou));
        errno = 0;
        CHECK(tcflow(STDIN_FILENO, TCOOFF) == -1 && errno == EINTR);
        CHECK(await_ttou(++expected_ttou));
        errno = 0;
        CHECK(tcsetpgrp(STDIN_FILENO, getpgrp()) == -1 && errno == EINTR);
        CHECK(tcgetpgrp(STDIN_FILENO) == parent_group);
        CHECK(await_ttou(++expected_ttou));
        sigset_t mask;
        CHECK(sigemptyset(&mask) == 0 && sigaddset(&mask, SIGTTOU) == 0);
        CHECK(sigprocmask(SIG_BLOCK, &mask, NULL) == 0);
        for (unsigned index = 0; index < sizeof(settings) / sizeof(settings[0]); ++index)
            CHECK(tcsetattr(STDIN_FILENO, settings[index], &attributes) == 0);
        CHECK(tcdrain(STDIN_FILENO) == 0);
        CHECK(tcflush(STDIN_FILENO, TCIOFLUSH) == 0);
        CHECK(tcflow(STDIN_FILENO, TCOOFF) == 0);
        CHECK(tcflow(STDIN_FILENO, TCOON) == 0);
        CHECK(write(STDOUT_FILENO, "allowed", 7) == 7);
        CHECK(sigaddset(&mask, SIGTTIN) == 0);
        CHECK(sigprocmask(SIG_BLOCK, &mask, NULL) == 0);
        errno = 0;
        CHECK(read(STDIN_FILENO, &byte, 1) == -1 && errno == EIO);
        CHECK(tcsetpgrp(STDIN_FILENO, getpgrp()) == 0);
        CHECK(tcgetpgrp(STDIN_FILENO) == getpgrp());
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(read(master, flow_bytes, sizeof(flow_bytes)) == 7);
    CHECK(memcmp(flow_bytes, "allowed", 7) == 0);
    // The session leader is now background and its group is orphaned.
    errno = 0;
    CHECK(tcsetpgrp(STDIN_FILENO, parent_group) == -1 && errno == EIO);
    action.sa_handler = SIG_IGN;
    CHECK(sigaction(SIGTTOU, &action, NULL) == 0);
    CHECK(tcsetpgrp(STDIN_FILENO, parent_group) == 0);
    pthread_t writer;
    CHECK(pthread_create(&writer, NULL, exercise_foreground_io, NULL) == 0);
    for (unsigned iteration = 0; iteration < 32; ++iteration)
        CHECK(tcgetpgrp(STDIN_FILENO) == parent_group);
    void *worker_result = NULL;
    CHECK(pthread_join(writer, &worker_result) == 0 && worker_result == NULL);
    char concurrent_bytes[32];
    CHECK(read(master, concurrent_bytes, sizeof(concurrent_bytes)) == 32);
    for (unsigned index = 0; index < sizeof(concurrent_bytes); ++index)
        CHECK(concurrent_bytes[index] == 'x');
    // Default stops are not caught-handler EINTR. The original operation must
    // finish after the shell promotes the job and continues it.
    for (unsigned mode = 0; mode < 5; ++mode) {
        CHECK(tcgetattr(STDIN_FILENO, &attributes) == 0);
        attributes.c_lflag |= TOSTOP;
        attributes.c_lflag &= ~(ECHO | ECHONL);
        CHECK(tcsetattr(STDIN_FILENO, TCSANOW, &attributes) == 0);
        child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            action.sa_handler = SIG_DFL;
            CHECK(sigaction(SIGTTIN, &action, NULL) == 0);
            CHECK(sigaction(SIGTTOU, &action, NULL) == 0);
            CHECK(setpgid(0, 0) == 0);
            if (mode == 0) {
                char input[7];
                CHECK(read(STDIN_FILENO, input, sizeof(input)) == 7);
                CHECK(memcmp(input, "resume\n", sizeof(input)) == 0);
            } else if (mode == 1) {
                CHECK(write(STDOUT_FILENO, "resumed", 7) == 7);
            } else if (mode == 2) {
                CHECK(tcflow(STDIN_FILENO, TCOOFF) == 0);
                CHECK(tcflow(STDIN_FILENO, TCOON) == 0);
            } else if (mode == 3) {
                CHECK(tcsetpgrp(STDIN_FILENO, getpgrp()) == 0);
            } else {
                pthread_t reader;
                CHECK(pthread_create(&reader, NULL, read_after_process_stop, NULL) == 0);
                void *read_result = NULL;
                CHECK(pthread_join(reader, &read_result) == 0 && read_result == NULL);
            }
            _exit(0);
        }
        CHECK(waitpid(child, &status, WUNTRACED) == child);
        CHECK(WIFSTOPPED(status));
        CHECK(WSTOPSIG(status) == (mode == 0 || mode == 4 ? SIGTTIN : SIGTTOU));
        CHECK(tcsetpgrp(STDIN_FILENO, child) == 0);
        if (mode == 0 || mode == 4) CHECK(write(master, "resume\n", 7) == 7);
        CHECK(kill(child, SIGCONT) == 0);
        CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        CHECK(tcsetpgrp(STDIN_FILENO, parent_group) == 0);
        if (mode == 1) {
            CHECK(read(master, flow_bytes, sizeof(flow_bytes)) == 7);
            CHECK(memcmp(flow_bytes, "resumed", 7) == 0);
        }
    }
    action.sa_handler = on_wait_signal;
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    CHECK(pthread_create(&writer, NULL, interrupt_handle_wait, NULL) == 0);
    char interrupted_byte;
    errno = 0;
    CHECK(read(STDIN_FILENO, &interrupted_byte, 1) == -1 && errno == EINTR);
    CHECK(waited_signal == 1);
    CHECK(pthread_join(writer, &worker_result) == 0 && worker_result == NULL);
    action.sa_flags = SA_RESTART;
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    struct sigaction installed;
    CHECK(sigaction(SIGUSR1, NULL, &installed) == 0);
    CHECK(installed.sa_flags == SA_RESTART);
    CHECK(pthread_create(&writer, NULL, complete_restarted_read, &master) == 0);
    char restarted_bytes[2];
    CHECK(read(STDIN_FILENO, restarted_bytes, sizeof(restarted_bytes)) == 2);
    CHECK(memcmp(restarted_bytes, "r\n", 2) == 0 && waited_signal == 2);
    CHECK(pthread_join(writer, &worker_result) == 0 && worker_result == NULL);
    CHECK(pthread_create(&writer, NULL, interrupt_handle_wait, NULL) == 0);
    struct timespec sleep_request = {1, 0}, remaining = {0};
    errno = 0;
    CHECK(nanosleep(&sleep_request, &remaining) == -1 && errno == EINTR);
    CHECK(waited_signal == 3 && remaining.tv_sec >= 0 && remaining.tv_sec <= 1);
    CHECK(pthread_join(writer, &worker_result) == 0 && worker_result == NULL);
    for (unsigned writing = 0; writing < 2; ++writing) {
        for (unsigned restart = 0; restart < 2; ++restart) {
            CHECK(pipe(pipes) == 0);
            size_t filled = 0;
            char block[512];
            memset(block, 'b', sizeof(block));
            if (writing) {
                CHECK(fcntl(pipes[1], F_SETFL, O_NONBLOCK) == 0);
                for (;;) {
                    ssize_t count = write(pipes[1], block, sizeof(block));
                    if (count < 0) { CHECK(errno == EAGAIN); break; }
                    CHECK(count == (ssize_t)sizeof(block));
                    filled += (size_t)count;
                }
                CHECK(filled > 0 && fcntl(pipes[1], F_SETFL, 0) == 0);
            }
            action.sa_flags = restart ? SA_RESTART : 0;
            CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
            struct stream_wakeup wake = {
                restart ? pipes[writing ? 0 : 1] : -1, (int)writing, waited_signal
            };
            CHECK(pthread_create(&writer, NULL, interrupt_stream_io, &wake) == 0);
            char byte = 'z';
            errno = 0;
            ssize_t count = writing ? write(pipes[1], &byte, 1) : read(pipes[0], &byte, 1);
            if (restart) CHECK(count == 1 && (writing || byte == 'p'));
            else CHECK(count == -1 && errno == EINTR);
            CHECK(pthread_join(writer, &worker_result) == 0 && worker_result == NULL);
            CHECK((fcntl(pipes[writing ? 1 : 0], F_GETFL) & O_NONBLOCK) == 0);
            if (writing) {
                CHECK(fcntl(pipes[0], F_SETFL, O_NONBLOCK) == 0);
                size_t received = 0;
                char last = 0;
                for (;;) {
                    ssize_t chunk = read(pipes[0], block, sizeof(block));
                    if (chunk < 0) { CHECK(errno == EAGAIN); break; }
                    CHECK(chunk > 0);
                    received += (size_t)chunk;
                    last = block[chunk - 1];
                }
                CHECK(received == filled && last == (restart ? 'z' : 'b'));
            }
            CHECK(close(pipes[0]) == 0 && close(pipes[1]) == 0);
        }
    }
    debug("native-terminal-window: PASS wait guard validation and stale epoch, pipe/terminal signal regressions\n");
    CHECK(close(master) == 0);
    return 0;
}
