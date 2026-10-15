#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { printf("child-startup: FAIL line=%d errno=%d\n", __LINE__, errno); return 1; } } while (0)
static int64_t cs_handle_count(void) {
    uint64_t number = 680;
    __asm__ volatile("syscall" : "+a"(number) : "D"(0), "S"(0) : "rcx", "r11", "memory");
    return (int64_t)number;
}

int main(void) {
    struct rlimit original, limit;
    CHECK(getrlimit(RLIMIT_AS, &original) == 0);
    limit = original; limit.rlim_cur = 0;
    /* No child can map its new resource-policy page at AS=0. Both APIs
     * must report that error, not a PID or an empty-stream exec success. */
    int64_t handles = cs_handle_count(); CHECK(handles > 0);
    CHECK(setrlimit(RLIMIT_AS, &limit) == 0);
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        errno = 0;
        pid_t child = fork();
        if (child == 0) _exit(88);
        CHECK(child == -1 && errno == ENOMEM);
        pid_t output = 12345;
        char *arguments[] = { "compositor.service", NULL };
        char *environment[] = { NULL };
        errno = EDOM;
        CHECK(posix_spawn(&output, "/system/services/compositor.service", NULL,
                          NULL, arguments, environment) == ENOMEM);
        CHECK(output == 12345 && errno == EDOM);
        CHECK(cs_handle_count() == handles);
    }
    CHECK(setrlimit(RLIMIT_AS, &original) == 0);
    errno = 0;
    CHECK(waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD);
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) _exit(19);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 19);
    CHECK(cs_handle_count() == handles);
    puts("child-startup: PASS fork and spawn propagate startup ENOMEM, preserve pid/errno, reclaim failed children and Handles; retry succeeds");
    return 0;
}
