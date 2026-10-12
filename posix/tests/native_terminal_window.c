#define _GNU_SOURCE 1
/* Isolated Compositor-slot KVM test: real newlib -> HandleControl -> PTY
 * provider and service-owned foreground signal delivery, not a desktop test. */
#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <poll.h>
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
static _Atomic unsigned pipe_signals;
static _Atomic unsigned child_signals;
static _Atomic unsigned directed_ready, directed_signals;
static _Atomic unsigned sync_ready, sync_completed, sync_unrelated;
static void on_sync_unrelated(int signal_number) {
    if (signal_number == SIGUSR2) atomic_fetch_add(&sync_unrelated, 1);
}
static pthread_t directed_handler_thread;
static void on_directed(int signal_number) {
    if (signal_number == SIGUSR1) {
        directed_handler_thread = pthread_self();
        atomic_fetch_add(&directed_signals, 1);
    }
}
static void on_child(int signal_number) {
    if (signal_number == SIGCHLD) atomic_fetch_add(&child_signals, 1);
}
static pthread_t pipe_handler_thread;
static void on_pipe(int signal_number) {
    if (signal_number == SIGPIPE) {
        pipe_handler_thread = pthread_self();
        atomic_fetch_add(&pipe_signals, 1);
    }
}
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
struct native_wait_item { uint32_t handle, minimum_write_bytes; uint64_t interests, observed; };
static int64_t native_call4(uint64_t number, uint64_t first, uint64_t second, uint64_t third, uint64_t fourth) {
    register uint64_t argument __asm__("r10") = fourth;
    __asm__ volatile("syscall" : "+a"(number)
        : "D"(first), "S"(second), "d"(third), "r"(argument)
        : "rcx", "r11", "memory");
    return (int64_t)number;
}
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

static void *return_immediately(void *argument) {
    errno = EBUSY; // Exercise the per-thread reent immediately before exit.
    return argument;
}

static _Atomic unsigned detached_returns;
static void *return_detached(void *unused) {
    (void)unused;
    errno = EBUSY;
    atomic_fetch_add(&detached_returns, 1);
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

static void *blocked_pipe_writer(void *context) {
    int fd = *(int *)context;
    sigset_t mask, pending;
    unsigned before = atomic_load(&pipe_signals);
    if (sigemptyset(&mask) != 0 || sigaddset(&mask, SIGPIPE) != 0
        || pthread_sigmask(SIG_BLOCK, &mask, NULL) != 0)
        return (void *)(uintptr_t)1;
    errno = 0;
    if (write(fd, "x", 1) != -1 || errno != EPIPE
        || atomic_load(&pipe_signals) != before || sigpending(&pending) != 0
        || sigismember(&pending, SIGPIPE) != 1)
        return (void *)(uintptr_t)1;
    if (pthread_sigmask(SIG_UNBLOCK, &mask, NULL) != 0
        || atomic_load(&pipe_signals) != before + 1
        || !pthread_equal(pipe_handler_thread, pthread_self()))
        return (void *)(uintptr_t)1;
    return NULL;
}

static void *close_pipe_reader(void *context) {
    struct timespec pause = {0, 100000000};
    if (nanosleep(&pause, NULL) != 0 || close(*(int *)context) != 0)
        return (void *)(uintptr_t)1;
    return NULL;
}

static void *continue_then_make_readable(void *context) {
    sigset_t mask;
    if (sigemptyset(&mask) != 0 || sigaddset(&mask, SIGUSR1) != 0
        || pthread_sigmask(SIG_BLOCK, &mask, NULL) != 0)
        return (void *)(uintptr_t)1;
    struct timespec pause = {0, 50000000};
    if (nanosleep(&pause, NULL) != 0 || kill(getpid(), SIGCONT) != 0
        || nanosleep(&pause, NULL) != 0 || write(*(int *)context, "m", 1) != 1)
        return (void *)(uintptr_t)1;
    return NULL;
}

static void *signal_then_make_readable(void *context) {
    if (interrupt_handle_wait(NULL) != NULL || write(*(int *)context, "s", 1) != 1)
        return (void *)(uintptr_t)1;
    return NULL;
}

static void *continue_then_interrupt(void *unused) {
    (void)unused;
    struct timespec pause = {0, 50000000};
    if (nanosleep(&pause, NULL) != 0 || kill(getpid(), SIGCONT) != 0)
        return (void *)(uintptr_t)1;
    return interrupt_handle_wait(NULL);
}

static void *wait_sync_signal(void *unused) {
    (void)unused;
    sigset_t set, current;
    if (sigemptyset(&set) != 0 || sigaddset(&set, SIGUSR1) != 0)
        return (void *)(uintptr_t)1;
    atomic_fetch_add(&sync_ready, 1);
    int selected = 0;
    errno = 123;
    if (sigwait(&set, &selected) != 0 || selected != SIGUSR1 || errno != 123
        || pthread_sigmask(SIG_SETMASK, NULL, &current) != 0
        || sigismember(&current, SIGUSR1) != 1)
        return (void *)(uintptr_t)1;
    atomic_fetch_add(&sync_completed, 1);
    return NULL;
}

static void *receive_directed_signal(void *unused) {
    (void)unused;
    sigset_t blocked, empty;
    if (sigemptyset(&blocked) != 0 || sigaddset(&blocked, SIGUSR1) != 0
        || sigemptyset(&empty) != 0 || pthread_sigmask(SIG_BLOCK, &blocked, NULL) != 0)
        return (void *)(uintptr_t)1;
    atomic_store(&directed_ready, 1);
    while (atomic_load(&directed_signals) == 0) {
        if (sigsuspend(&empty) != -1 || errno != EINTR) return (void *)(uintptr_t)1;
    }
    return pthread_equal(directed_handler_thread, pthread_self()) ? NULL : (void *)(uintptr_t)1;
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
    uint32_t native_pair[2];
    CHECK(native_call4(649, (uintptr_t)native_pair, 0, 0, 0) == 0);
    char capacity_block[512];
    memset(capacity_block, 'c', sizeof(capacity_block));
    for (;;) {
        int64_t count = native_call4(675, native_pair[1], (uintptr_t)capacity_block, sizeof(capacity_block), 3);
        if (count < 0) { CHECK(count == -EAGAIN); break; }
        CHECK(count == 512);
    }
    struct native_wait_item capacity_wait = {native_pair[1], 512, 4, 0};
    CHECK(native_call4(647, (uintptr_t)&capacity_wait, 1, 0, 0) == -EAGAIN);
    CHECK(native_call4(681, native_pair[0], (uintptr_t)capacity_block, 1, 2) == 1);
    CHECK(native_call4(647, (uintptr_t)&capacity_wait, 1, 0, 0) == -EAGAIN);
    capacity_wait.minimum_write_bytes = 0;
    CHECK(native_call4(647, (uintptr_t)&capacity_wait, 1, 0, 0) == 0);
    capacity_wait.minimum_write_bytes = 512;
    CHECK(native_call4(681, native_pair[0], (uintptr_t)capacity_block, 511, 2) == 511);
    CHECK(native_call4(647, (uintptr_t)&capacity_wait, 1, 0, 0) == 0);
    CHECK((capacity_wait.observed & 4) != 0);
    CHECK(native_call4(675, native_pair[1], (uintptr_t)capacity_block, 512, 3) == 512);
    capacity_wait.minimum_write_bytes = UINT32_MAX;
    CHECK(native_call4(647, (uintptr_t)&capacity_wait, 1, 0, 0) == -EINVAL);
    capacity_wait.minimum_write_bytes = 512;
    capacity_wait.handle = native_pair[0];
    CHECK(native_call4(647, (uintptr_t)&capacity_wait, 1, 0, 0) == -EINVAL);
    CHECK(native_call4(626, native_pair[0], 0, 0, 0) == 0);
    CHECK(native_call4(626, native_pair[1], 0, 0, 0) == 0);
    debug("native-terminal-window: capacity thresholds passed\n");
    for (uintptr_t iteration = 1; iteration <= 128; ++iteration) {
        pthread_t thread;
        void *result = NULL;
        CHECK(pthread_create(&thread, NULL, return_immediately, (void *)iteration) == 0);
        CHECK(pthread_join(thread, &result) == 0 && result == (void *)iteration);
    }
    debug("native-terminal-window: 128 native thread retirements passed\n");
    pthread_attr_t detached;
    CHECK(pthread_attr_init(&detached) == 0);
    CHECK(pthread_attr_setdetachstate(&detached, PTHREAD_CREATE_DETACHED) == 0);
    for (unsigned iteration = 1; iteration <= 128; ++iteration) {
        pthread_t thread;
        CHECK(pthread_create(&thread, &detached, return_detached, NULL) == 0);
        for (unsigned retry = 0; retry < 1000 && atomic_load(&detached_returns) < iteration; ++retry) {
            struct timespec pause = {0, 1000000};
            CHECK(nanosleep(&pause, NULL) == 0);
        }
        CHECK(atomic_load(&detached_returns) == iteration);
    }
    CHECK(pthread_attr_destroy(&detached) == 0);
    debug("native-terminal-window: 128 detached retirements passed\n");
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
    for (unsigned restart = 0; restart < 2; ++restart) {
        action.sa_flags = restart ? SA_RESTART : 0;
        CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
        for (unsigned mode = 0; mode < 4; ++mode) {
            CHECK(pipe(pipes) == 0);
            CHECK(pthread_create(&writer, NULL, interrupt_handle_wait, NULL) == 0);
            sig_atomic_t before = atomic_load(&waited_signal);
            struct pollfd descriptor = {pipes[0], POLLIN, 0};
            fd_set readable;
            FD_ZERO(&readable);
            FD_SET(pipes[0], &readable);
            struct timeval timeout = {1, 0};
            errno = 0;
            int result;
            if (mode == 0) result = poll(&descriptor, 1, 1000);
            else if (mode == 1) result = select(pipes[0] + 1, &readable, NULL, NULL, &timeout);
            else if (mode == 2) result = poll(NULL, 0, 1000);
            else result = select(0, NULL, NULL, NULL, &timeout);
            CHECK(result == -1 && errno == EINTR && atomic_load(&waited_signal) == before + 1);
            CHECK(pthread_join(writer, &worker_result) == 0 && worker_result == NULL);
            CHECK(close(pipes[0]) == 0 && close(pipes[1]) == 0);
        }
    }
    for (unsigned selecting = 0; selecting < 2; ++selecting) {
        CHECK(pipe(pipes) == 0);
        CHECK(pthread_create(&writer, NULL, continue_then_make_readable, &pipes[1]) == 0);
        struct pollfd descriptor = {pipes[0], POLLIN, 0};
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(pipes[0], &readable);
        struct timeval timeout = {1, 0};
        int result = selecting ? select(pipes[0] + 1, &readable, NULL, NULL, &timeout)
            : poll(&descriptor, 1, 1000);
        CHECK(result == 1 && (selecting ? FD_ISSET(pipes[0], &readable) : (descriptor.revents & POLLIN) != 0));
        char byte = 0;
        CHECK(read(pipes[0], &byte, 1) == 1 && byte == 'm');
        CHECK(pthread_join(writer, &worker_result) == 0 && worker_result == NULL);
        CHECK(close(pipes[0]) == 0 && close(pipes[1]) == 0);
    }
    debug("native-terminal-window: multiplex interruption and unrelated wakeups passed\n");
    sigset_t block_user, empty_mask, original_mask, restored_mask;
    CHECK(sigemptyset(&block_user) == 0 && sigaddset(&block_user, SIGUSR1) == 0);
    CHECK(sigemptyset(&empty_mask) == 0);
    CHECK(pthread_sigmask(SIG_BLOCK, &block_user, &original_mask) == 0);
    for (unsigned polling = 0; polling < 2; ++polling) {
        sig_atomic_t before = atomic_load(&waited_signal);
        CHECK(kill(getpid(), SIGUSR1) == 0);
        struct timespec timeout = {1, 123456789}, unchanged = timeout;
        errno = 0;
        int result = polling ? ppoll(NULL, 0, &timeout, &empty_mask)
            : pselect(0, NULL, NULL, NULL, &timeout, &empty_mask);
        CHECK(result == -1 && errno == EINTR && atomic_load(&waited_signal) == before + 1);
        CHECK(memcmp(&timeout, &unchanged, sizeof(timeout)) == 0);
        CHECK(pthread_sigmask(SIG_SETMASK, NULL, &restored_mask) == 0);
        CHECK(sigismember(&restored_mask, SIGUSR1) == 1);
    }
    struct timespec zero_timeout = {0, 0};
    struct timespec invalid_timeout = {0, 1000000000};
    errno = 0;
    CHECK(ppoll(NULL, 0, &invalid_timeout, &empty_mask) == -1 && errno == EINVAL);
    CHECK(ppoll(NULL, 0, &zero_timeout, &empty_mask) == 0);
    errno = 0;
    CHECK(ppoll(NULL, 65, &zero_timeout, &empty_mask) == -1 && errno == EINVAL);
    fd_set invalid_set;
    FD_ZERO(&invalid_set);
    FD_SET(63, &invalid_set);
    errno = 0;
    CHECK(pselect(64, &invalid_set, NULL, NULL, &zero_timeout, &empty_mask) == -1 && errno == EBADF);
    CHECK(pthread_sigmask(SIG_SETMASK, NULL, &restored_mask) == 0);
    CHECK(sigismember(&restored_mask, SIGUSR1) == 1);
    CHECK(pthread_sigmask(SIG_SETMASK, &original_mask, NULL) == 0);
    for (unsigned polling = 0; polling < 2; ++polling) {
        CHECK(pipe(pipes) == 0);
        sig_atomic_t before = atomic_load(&waited_signal);
        CHECK(pthread_create(&writer, NULL, signal_then_make_readable, &pipes[1]) == 0);
        struct timespec timeout = {1, 0};
        struct pollfd descriptor = {pipes[0], POLLIN, 0};
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(pipes[0], &readable);
        int result = polling ? ppoll(&descriptor, 1, &timeout, &block_user)
            : pselect(pipes[0] + 1, &readable, NULL, NULL, &timeout, &block_user);
        CHECK(result == 1 && atomic_load(&waited_signal) == before + 1);
        CHECK(pthread_sigmask(SIG_SETMASK, NULL, &restored_mask) == 0);
        CHECK(sigismember(&restored_mask, SIGUSR1) == sigismember(&original_mask, SIGUSR1));
        char byte = 0;
        CHECK(read(pipes[0], &byte, 1) == 1 && byte == 's');
        CHECK(pthread_join(writer, &worker_result) == 0 && worker_result == NULL);
        CHECK(close(pipes[0]) == 0 && close(pipes[1]) == 0);
    }
    debug("native-terminal-window: pselect/ppoll masks, pending entry and restoration passed\n");
    for (unsigned restart = 0; restart < 2; ++restart) {
        action.sa_flags = restart ? SA_RESTART : 0;
        CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
        sig_atomic_t before = atomic_load(&waited_signal);
        CHECK(pthread_create(&writer, NULL, continue_then_interrupt, NULL) == 0);
        errno = 0;
        CHECK(pause() == -1 && errno == EINTR && atomic_load(&waited_signal) == before + 1);
        CHECK(pthread_join(writer, &worker_result) == 0 && worker_result == NULL);
        CHECK(pthread_sigmask(SIG_SETMASK, NULL, &restored_mask) == 0);
        CHECK(memcmp(&restored_mask, &original_mask, sizeof(restored_mask)) == 0);
        CHECK(pthread_sigmask(SIG_BLOCK, &block_user, NULL) == 0);
        before = atomic_load(&waited_signal);
        CHECK(raise(SIGUSR1) == 0 && atomic_load(&waited_signal) == before);
        errno = 0;
        CHECK(sigsuspend(&empty_mask) == -1 && errno == EINTR && atomic_load(&waited_signal) == before + 1);
        CHECK(pthread_sigmask(SIG_SETMASK, NULL, &restored_mask) == 0);
        CHECK(sigismember(&restored_mask, SIGUSR1) == 1);
        CHECK(pthread_sigmask(SIG_SETMASK, &original_mask, NULL) == 0);
    }
    errno = 0;
    CHECK(sigsuspend(NULL) == -1 && errno == EFAULT);
    debug("native-terminal-window: pause/sigsuspend handlers and mask restoration passed\n");
    for (unsigned restart = 0; restart < 2; ++restart) {
        action.sa_flags = restart ? SA_RESTART : 0;
        CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
        CHECK(pipe(pipes) == 0);
        pid_t waiting_child = fork();
        CHECK(waiting_child >= 0);
        if (waiting_child == 0) {
            char byte = 0;
            if (close(pipes[1]) != 0 || read(pipes[0], &byte, 1) != 1 || byte != 'p') _exit(82);
            _exit(42);
        }
        CHECK(close(pipes[0]) == 0);
        sig_atomic_t before = atomic_load(&waited_signal);
        struct stream_wakeup wake = {restart ? pipes[1] : -1, 0, before};
        CHECK(pthread_create(&writer, NULL, interrupt_stream_io, &wake) == 0);
        int child_status = 0;
        errno = 0;
        pid_t result = waitpid(waiting_child, &child_status, 0);
        if (restart) {
            CHECK(result == waiting_child && WIFEXITED(child_status) && WEXITSTATUS(child_status) == 42);
        } else {
            CHECK(result == -1 && errno == EINTR);
            CHECK(waitpid(waiting_child, &child_status, WNOHANG) == 0);
        }
        CHECK(atomic_load(&waited_signal) == before + 1);
        CHECK(pthread_join(writer, &worker_result) == 0 && worker_result == NULL);
        if (!restart) {
            CHECK(write(pipes[1], "p", 1) == 1);
            CHECK(waitpid(waiting_child, &child_status, 0) == waiting_child);
            CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 42);
        }
        CHECK(close(pipes[1]) == 0);
    }
    debug("native-terminal-window: waitpid EINTR, restart and unreaped child status passed\n");
    struct sigaction child_action, previous_child_action;
    memset(&child_action, 0, sizeof(child_action));
    CHECK(sigemptyset(&child_action.sa_mask) == 0);
    child_action.sa_handler = SIG_IGN;
    CHECK(sigaction(SIGCHLD, &child_action, &previous_child_action) == 0);
    pid_t ignored_child = fork();
    CHECK(ignored_child >= 0);
    if (ignored_child == 0) _exit(7);
    unsigned ignored_retry;
    for (ignored_retry = 0; ignored_retry < 1000; ++ignored_retry) {
        errno = 0;
        if (getpgid(ignored_child) == -1) {
            CHECK(errno == ESRCH);
            break;
        }
        struct timespec delay = {0, 1000000};
        CHECK(nanosleep(&delay, NULL) == 0);
    }
    CHECK(ignored_retry < 1000); // No wait call was needed to reclaim the child.
    int ignored_status = 99;
    errno = 0;
    CHECK(waitpid(ignored_child, &ignored_status, 0) == -1 && errno == ECHILD && ignored_status == 99);
    CHECK(sigaction(SIGCHLD, &previous_child_action, NULL) == 0);
    pid_t normal_child = fork();
    CHECK(normal_child >= 0);
    if (normal_child == 0) _exit(8);
    CHECK(waitpid(normal_child, &ignored_status, 0) == normal_child);
    CHECK(WIFEXITED(ignored_status) && WEXITSTATUS(ignored_status) == 8);
    debug("native-terminal-window: explicit SIGCHLD ignore reaps without retaining status\n");
    CHECK(raise(SIGCONT) == 0); // Drain prior default SIGCHLD deliveries first.
    child_action.sa_handler = on_child;
    child_action.sa_flags = SA_NOCLDWAIT | SA_RESTART;
    CHECK(sigaction(SIGCHLD, &child_action, NULL) == 0);
    struct sigaction queried_child_action;
    CHECK(sigaction(SIGCHLD, NULL, &queried_child_action) == 0);
    CHECK((queried_child_action.sa_flags & SA_NOCLDWAIT) != 0);
    pid_t no_wait_child = fork();
    CHECK(no_wait_child >= 0);
    if (no_wait_child == 0) _exit(9);
    for (ignored_retry = 0; ignored_retry < 1000; ++ignored_retry) {
        errno = 0;
        if (getpgid(no_wait_child) == -1) {
            CHECK(errno == ESRCH);
            break;
        }
        struct timespec delay = {0, 1000000};
        CHECK(nanosleep(&delay, NULL) == 0 || errno == EINTR);
    }
    CHECK(ignored_retry < 1000);
    for (ignored_retry = 0; ignored_retry < 1000 && atomic_load(&child_signals) == 0; ++ignored_retry) {
        struct timespec delay = {0, 1000000};
        CHECK(nanosleep(&delay, NULL) == 0 || errno == EINTR);
    }
    CHECK(atomic_load(&child_signals) == 1);
    errno = 0;
    CHECK(waitpid(no_wait_child, &ignored_status, 0) == -1 && errno == ECHILD);
    CHECK(sigaction(SIGCHLD, &previous_child_action, NULL) == 0);
    debug("native-terminal-window: SA_NOCLDWAIT retains handler notification without zombie status\n");
    action.sa_handler = on_directed;
    action.sa_flags = 0;
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    CHECK(pthread_create(&writer, NULL, receive_directed_signal, NULL) == 0);
    errno = 123;
    CHECK(pthread_kill(writer, -1) == EINVAL && errno == 123);
    CHECK(pthread_kill(writer, 0) == 0 && errno == 123);
    for (unsigned retry = 0; retry < 1000 && atomic_load(&directed_ready) == 0; ++retry) {
        struct timespec delay = {0, 1000000};
        CHECK(nanosleep(&delay, NULL) == 0);
    }
    CHECK(atomic_load(&directed_ready) == 1);
    CHECK(pthread_kill(writer, SIGUSR1) == 0);
    CHECK(pthread_join(writer, &worker_result) == 0 && worker_result == NULL);
    CHECK(atomic_load(&directed_signals) == 1 && pthread_equal(directed_handler_thread, writer));
    errno = 123;
    CHECK(pthread_kill(writer, 0) == ESRCH && errno == 123);
    CHECK(pthread_kill(pthread_self(), SIGUSR1) == 0);
    CHECK(atomic_load(&directed_signals) == 2 && pthread_equal(directed_handler_thread, pthread_self()));
    sigset_t sync_set, sync_old, sync_pending;
    CHECK(sigemptyset(&sync_set) == 0 && sigaddset(&sync_set, SIGUSR1) == 0);
    CHECK(pthread_sigmask(SIG_BLOCK, &sync_set, &sync_old) == 0);
    CHECK(raise(SIGUSR1) == 0);
    int selected_signal = 99;
    errno = 123;
    CHECK(sigwait(&sync_set, &selected_signal) == 0 && selected_signal == SIGUSR1 && errno == 123);
    CHECK(atomic_load(&directed_signals) == 2);
    CHECK(sigpending(&sync_pending) == 0 && sigismember(&sync_pending, SIGUSR1) == 0);
    CHECK(kill(getpid(), SIGUSR1) == 0);
    CHECK(sigwait(&sync_set, &selected_signal) == 0 && selected_signal == SIGUSR1);
    CHECK(sigwait(NULL, &selected_signal) == EFAULT && errno == 123);
    CHECK(sigwait(&sync_set, NULL) == EFAULT && errno == 123);
    sigset_t unblocked_set;
    CHECK(sigemptyset(&unblocked_set) == 0 && sigaddset(&unblocked_set, SIGUSR2) == 0);
    selected_signal = 99;
    CHECK(sigwait(&unblocked_set, &selected_signal) == EINVAL && selected_signal == 99 && errno == 123);
    struct sigaction unrelated_action, old_unrelated_action;
    memset(&unrelated_action, 0, sizeof(unrelated_action));
    unrelated_action.sa_handler = on_sync_unrelated;
    CHECK(sigemptyset(&unrelated_action.sa_mask) == 0);
    CHECK(sigaction(SIGUSR2, &unrelated_action, &old_unrelated_action) == 0);
    CHECK(pthread_create(&writer, NULL, wait_sync_signal, NULL) == 0);
    for (unsigned retry = 0; retry < 1000 && atomic_load(&sync_ready) == 0; ++retry) {
        struct timespec delay = {0, 1000000};
        CHECK(nanosleep(&delay, NULL) == 0);
    }
    CHECK(atomic_load(&sync_ready) == 1);
    struct timespec settle_wait = {0, 50000000};
    CHECK(nanosleep(&settle_wait, NULL) == 0);
    CHECK(pthread_kill(writer, SIGUSR2) == 0);
    for (unsigned retry = 0; retry < 1000 && atomic_load(&sync_unrelated) == 0; ++retry) {
        struct timespec delay = {0, 1000000};
        CHECK(nanosleep(&delay, NULL) == 0);
    }
    CHECK(atomic_load(&sync_unrelated) == 1 && atomic_load(&sync_completed) == 0);
    CHECK(pthread_kill(writer, SIGUSR1) == 0);
    CHECK(pthread_join(writer, &worker_result) == 0 && worker_result == NULL);
    CHECK(atomic_load(&sync_completed) == 1 && atomic_load(&directed_signals) == 2);
    pthread_t sync_second;
    CHECK(pthread_create(&writer, NULL, wait_sync_signal, NULL) == 0);
    CHECK(pthread_create(&sync_second, NULL, wait_sync_signal, NULL) == 0);
    for (unsigned retry = 0; retry < 1000 && atomic_load(&sync_ready) < 3; ++retry) {
        struct timespec delay = {0, 1000000};
        CHECK(nanosleep(&delay, NULL) == 0);
    }
    CHECK(atomic_load(&sync_ready) == 3);
    CHECK(kill(getpid(), SIGUSR1) == 0);
    for (unsigned retry = 0; retry < 1000 && atomic_load(&sync_completed) < 2; ++retry) {
        struct timespec delay = {0, 1000000};
        CHECK(nanosleep(&delay, NULL) == 0);
    }
    CHECK(atomic_load(&sync_completed) == 2);
    CHECK(kill(getpid(), SIGUSR1) == 0);
    CHECK(pthread_join(writer, &worker_result) == 0 && worker_result == NULL);
    CHECK(pthread_join(sync_second, &worker_result) == 0 && worker_result == NULL);
    CHECK(atomic_load(&sync_completed) == 3 && atomic_load(&directed_signals) == 2);
    CHECK(sigaction(SIGUSR2, &old_unrelated_action, NULL) == 0);
    CHECK(pthread_sigmask(SIG_SETMASK, &sync_old, NULL) == 0);
    debug("native-terminal-window: sigwait pending, deferred, interrupted and competing waiters passed\n");
    action.sa_handler = on_wait_signal;
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    debug("native-terminal-window: pthread_kill attached target, self delivery and return codes passed\n");
    struct sigaction pipe_action;
    memset(&pipe_action, 0, sizeof(pipe_action));
    pipe_action.sa_handler = on_pipe;
    CHECK(sigemptyset(&pipe_action.sa_mask) == 0);
    CHECK(sigaction(SIGPIPE, &pipe_action, NULL) == 0);
    CHECK(pipe(pipes) == 0 && close(pipes[0]) == 0);
    CHECK(write(pipes[1], "", 0) == 0 && atomic_load(&pipe_signals) == 0);
    errno = 0;
    CHECK(write(pipes[1], "x", 1) == -1 && errno == EPIPE);
    CHECK(atomic_load(&pipe_signals) == 1 && pthread_equal(pipe_handler_thread, pthread_self()));
    CHECK(pthread_create(&writer, NULL, blocked_pipe_writer, &pipes[1]) == 0);
    CHECK(pthread_join(writer, &worker_result) == 0 && worker_result == NULL);
    CHECK(atomic_load(&pipe_signals) == 2);
    CHECK(raise(SIGPIPE) == 0 && atomic_load(&pipe_signals) == 3);
    pipe_action.sa_handler = SIG_IGN;
    CHECK(sigaction(SIGPIPE, &pipe_action, NULL) == 0);
    errno = 0;
    CHECK(write(pipes[1], "x", 1) == -1 && errno == EPIPE && atomic_load(&pipe_signals) == 3);
    CHECK(close(pipes[1]) == 0);
    pipe_action.sa_handler = on_pipe;
    CHECK(sigaction(SIGPIPE, &pipe_action, NULL) == 0);
    CHECK(pipe(pipes) == 0);
    CHECK(pthread_create(&writer, NULL, close_pipe_reader, &pipes[0]) == 0);
    static char large_write[131072];
    ssize_t prefix = write(pipes[1], large_write, sizeof(large_write));
    CHECK(prefix > 0 && prefix < (ssize_t)sizeof(large_write) && atomic_load(&pipe_signals) == 4);
    CHECK(pthread_join(writer, &worker_result) == 0 && worker_result == NULL);
    CHECK(close(pipes[1]) == 0);
    CHECK(pipe(pipes) == 0 && close(pipes[0]) == 0);
    pid_t broken_child = fork();
    CHECK(broken_child >= 0);
    if (broken_child == 0) {
        pipe_action.sa_handler = SIG_DFL;
        if (sigaction(SIGPIPE, &pipe_action, NULL) != 0) _exit(80);
        (void)write(pipes[1], "x", 1);
        _exit(81);
    }
    int broken_status = 0;
    CHECK(waitpid(broken_child, &broken_status, 0) == broken_child);
    CHECK(WIFSIGNALED(broken_status) && WTERMSIG(broken_status) == SIGPIPE);
    CHECK(close(pipes[1]) == 0);
    debug("native-terminal-window: PASS sigwait and POSIX signal regressions\n");
    CHECK(close(master) == 0);
    return 0;
}
