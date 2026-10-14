/* Compile the actual C variadic entry against host-only API doubles. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#define ioctl mochi_ioctl
#define fcntl mock_fcntl
#define tcgetattr mock_tcgetattr
#define tcsetattr mock_tcsetattr
#define tcgetwinsize mock_tcgetwinsize
#define tcsetwinsize mock_tcsetwinsize
#define tcgetpgrp mock_tcgetpgrp
#define tcsetpgrp mock_tcsetpgrp

static int operations, last_action, fail_group, nonblocking_calls, nonblocking_value, fail_nonblocking;
int __mochios_fd_set_nonblocking(int fd, int enabled) {
    assert(fd == 7 && (enabled == 0 || enabled == 1));
    ++nonblocking_calls;
    if (fail_nonblocking) { errno = EACCES; return -1; }
    nonblocking_value = enabled;
    return 0;
}
int mock_fcntl(int fd, int command, ...) {
    assert(command == F_GETFD);
    if (fd == -1) { errno = EBADF; return -1; }
    assert(fd == 7);
    return 0;
}
int mock_tcgetattr(int fd, struct termios *attributes) {
    assert(fd == 7); ++operations; attributes->c_iflag = 123; return 0;
}
int mock_tcsetattr(int fd, int action, const struct termios *attributes) {
    assert(fd == 7 && attributes->c_iflag == 123);
    ++operations; last_action = action; return 0;
}
int mock_tcgetwinsize(int fd, struct winsize *size) {
    assert(fd == 7); ++operations; size->ws_row = 42; return 0;
}
int mock_tcsetwinsize(int fd, const struct winsize *size) {
    assert(fd == 7 && size->ws_row == 42); ++operations; return 0;
}
pid_t mock_tcgetpgrp(int fd) {
    assert(fd == 7); ++operations;
    if (fail_group) { errno = EIO; return -1; }
    return 99;
}
int mock_tcsetpgrp(int fd, pid_t group) {
    assert(fd == 7 && group == 99); ++operations; return 0;
}

#include "../../../user/runtime/newlib_ioctl.c"

int main(void) {
    struct termios attributes = {0};
    struct winsize size = {0};
    pid_t group = -10;
    errno = 123;
    assert(mochi_ioctl(7, TCGETS, &attributes) == 0);
    assert(attributes.c_iflag == 123 && errno == 123);
    assert(mochi_ioctl(7, TCSETS, &attributes) == 0 && last_action == TCSANOW);
    assert(mochi_ioctl(7, TCSETSW, &attributes) == 0 && last_action == TCSADRAIN);
    assert(mochi_ioctl(7, TCSETSF, &attributes) == 0 && last_action == TCSAFLUSH);
    assert(mochi_ioctl(7, TIOCGWINSZ, &size) == 0 && size.ws_row == 42);
    assert(mochi_ioctl(7, TIOCSWINSZ, &size) == 0);
    assert(mochi_ioctl(7, TIOCGPGRP, &group) == 0 && group == 99);
    assert(mochi_ioctl(7, TIOCSPGRP, &group) == 0);
    assert(operations == 8);
    unsigned long requests[] = {TCGETS, TCSETS, TCSETSW, TCSETSF,
                                TIOCGPGRP, TIOCSPGRP, TIOCGWINSZ, TIOCSWINSZ, FIONBIO};
    for (unsigned index = 0; index < sizeof(requests) / sizeof(requests[0]); ++index) {
        assert(mochi_ioctl(7, requests[index], (void *)0) == -1 && errno == EFAULT);
        /* Bad descriptor rejection must happen before va_arg(). */
        assert(mochi_ioctl(-1, requests[index]) == -1 && errno == EBADF);
    }
    assert(mochi_ioctl(7, 0xdeadUL) == -1 && errno == ENOTTY);
    assert(mochi_ioctl(-1, 0xdeadUL) == -1 && errno == EBADF);
    assert(operations == 8);
    fail_group = 1;
    group = 1234;
    assert(mochi_ioctl(7, TIOCGPGRP, &group) == -1 && errno == EIO);
    assert(group == 1234);
    int enabled = -9;
    assert(mochi_ioctl(7, FIONBIO, &enabled) == 0 && nonblocking_value == 1);
    enabled = 0;
    assert(mochi_ioctl(7, FIONBIO, &enabled) == 0 && nonblocking_value == 0);
    enabled = 1;
    fail_nonblocking = 1;
    assert(mochi_ioctl(7, FIONBIO, &enabled) == -1 && errno == EACCES);
    assert(nonblocking_calls == 3 && nonblocking_value == 0);
    return 0;
}
