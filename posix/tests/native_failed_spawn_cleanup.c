/* Isolated Compositor-slot KVM probe, using its existing spawn capability.
 * A separate test readiness gate replaces Input; neither is a desktop test. */
#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "failed-spawn-cleanup: FAIL line %d errno %d\n", __LINE__, errno); \
        return 1; \
    } \
} while (0)

int main(void) {
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
    return 0;
}
