/* Isolated Compositor-slot KVM probe, using its existing spawn capability.
 * A separate test readiness gate replaces Input; neither is a desktop test. */
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
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

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--exec-child") == 0) {
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
    for (unsigned attempt = 0; attempt < 4; ++attempt) {
        int channel[2];
        CHECK(pipe(channel) == 0);
        int cloexec = dup(channel[1]);
        CHECK(cloexec == 5);
        CHECK(fcntl(cloexec, F_SETFD, FD_CLOEXEC) == 0);
        if (attempt < 2) {
            CHECK(posix_spawn_file_actions_init(&actions) == 0);
            CHECK(posix_spawn_file_actions_adddup2(&actions, channel[1], 9) == 0);
            CHECK(posix_spawn_file_actions_addclose(&actions, channel[0]) == 0);
            CHECK(posix_spawn_file_actions_addclose(&actions, channel[1]) == 0);
            CHECK(posix_spawn(&child, "/system/services/compositor.service", &actions,
                              NULL, exec_arguments, exec_environment) == 0);
            CHECK(posix_spawn_file_actions_destroy(&actions) == 0);
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
    return 0;
}
