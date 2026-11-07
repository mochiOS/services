/* Real C runtime regression; prepare Data inputs with native_replayed_exec.py. */
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
#define TARGET "/system/bin/exec-child"
#define LIBDIR "/system/libraries/exec-test"

static int launch(int which) {
    char *args[] = {"exec-child", "kept", NULL};
    printf("EXEC-TEST launching case=%d\n", which);
    if (setenv("EXEC_TEST", "kept", 1) || setenv("LD_LIBRARY_PATH", LIBDIR, 1))
        return 90;
    if (which == 4 && setenv("LD_LIBRARY_PATH", "/tmp/exec-test", 1)) return 91;
    switch (which) {
    case 0:
        execv(TARGET, args);
        break;
    case 1:
        execve(TARGET, args, environ);
        break;
    case 2: {
        int fd = open("/tmp/exec-test/exec-pinned", O_RDONLY);
        if (fd < 0) return 93;
        if (unlink("/tmp/exec-test/exec-pinned")) {
            fprintf(stderr, "EXEC-TEST unlink failed errno=%d\n", errno);
            close(fd);
            return 94;
        }
        puts("EXEC-TEST unlinked pinned image");
        fexecve(fd, args, environ);
        int error = errno;
        close(fd);
        errno = error;
        break;
    }
    case 3:
        execv("/tmp/exec-test/exec-tampered", args);
        break;
    case 4:
        execv(TARGET, args);
        break;
    case 5:
        execv("/system/bin/exec-extra", args);
        break;
    case 6:
        if (setenv("PATH", "/system/bin", 1)) return 95;
        execvp("exec-child", args);
        break;
    }
    int error = errno;
    fprintf(stderr, "EXEC-TEST rejected case=%d errno=%d\n", which, error);
    return (which >= 3 && which <= 5 && error == EACCES) ? 0 : 96;
}

int main(void) {
    if (!freopen("/tmp/exec-results.log", "a", stdout) ||
        !freopen("/tmp/exec-results.log", "a", stderr)) return 2;
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    puts("EXEC-TEST START");
    int failures = 0;
    for (int which = 0; which < 7; which++) {
        pid_t child = fork();
        if (child < 0) { puts("EXEC-TEST FAIL fork"); return 3; }
        if (child == 0) _exit(launch(which));
        int status = -1;
        if (waitpid(child, &status, 0) != child) {
            puts("EXEC-TEST FAIL wait");
            return 4;
        }
        int expected = (which >= 3 && which <= 5) ? 0 : 42;
        int ok = WIFEXITED(status) && WEXITSTATUS(status) == expected;
        printf("EXEC-TEST %s case=%d status=%d expected=%d\n",
               ok ? "PASS" : "FAIL", which, status, expected);
        failures += !ok;
    }
    pid_t child = 0;
    char *args[] = {"exec-child", "kept", NULL};
    if (setenv("EXEC_TEST", "kept", 1) || setenv("LD_LIBRARY_PATH", LIBDIR, 1)) return 5;
    int error = posix_spawn(&child, TARGET, NULL, NULL, args, environ), status = -1;
    int ok = !error && waitpid(child, &status, 0) == child &&
             WIFEXITED(status) && WEXITSTATUS(status) == 42;
    printf("EXEC-TEST %s case=spawn error=%d status=%d\n", ok ? "PASS" : "FAIL", error, status);
    failures += !ok;
    printf("EXEC-TEST COMPLETE failures=%d\n", failures);
    return failures ? 1 : 0;
}
