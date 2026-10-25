#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

_Static_assert(sizeof(struct utsname) == 1280, "uname ABI");
_Static_assert(sizeof(((struct utsname *)0)->nodename) == 256, "node ABI");

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "system-identity: FAIL line=%d: %s errno=%d\n", __LINE__, #x, errno); \
    return 1; } } while (0)

int mochi_system_identity_probe(void) {
    struct utsname original, current;
    char node[256];
    errno = 71;
    CHECK(uname(&original) == 0 && errno == 71);
    CHECK(!strcmp(original.sysname, "mochiOS"));
    CHECK(!strcmp(original.machine, "x86_64"));
    CHECK(original.release[0] && !strncmp(original.version, "build ", 6));
    CHECK(gethostname(node, sizeof(node)) == 0 && !strcmp(node, original.nodename));
    CHECK(errno == 71);
    CHECK(sysconf(_SC_HOST_NAME_MAX) == 255);
    CHECK(uname((struct utsname *)1) == -1 && errno == EFAULT);
    CHECK(gethostname((char *)1, sizeof(node)) == -1 && errno == EFAULT);
    CHECK(gethostname(node, 0) == -1 && errno == ENAMETOOLONG);
    CHECK(sethostname((const char *)1, sizeof(node)) == -1 && errno == EINVAL);
    if (geteuid() != 0) {
        CHECK(sethostname("forged-root", 11) == -1 && errno == EPERM);
        CHECK(uname(&current) == 0 && !strcmp(current.nodename, original.nodename));
    } else {
        CHECK(sethostname("compiler-test", 13) == 0);
        CHECK(uname(&current) == 0 && !strcmp(current.nodename, "compiler-test"));
        CHECK(gethostname(node, sizeof(node)) == 0 && !strcmp(node, "compiler-test"));
        pid_t child = fork();
        if (child == 0) {
            if (seteuid(501) || uname(&current) || strcmp(current.nodename, "compiler-test")) _exit(91);
            if (sethostname("denied", 6) != -1 || errno != EPERM) _exit(92);
            _exit(0);
        }
        int status = 0;
        int child_ok = child >= 0 && waitpid(child, &status, 0) == child && status == 0;
        CHECK(sethostname(original.nodename, strlen(original.nodename)) == 0);
        CHECK(child_ok);
        char maximum[255];
        memset(maximum, 'n', sizeof(maximum));
        CHECK(sethostname(maximum, sizeof(maximum)) == 0);
        int max_ok = gethostname(node, sizeof(node)) == 0 && node[255] == 0 && !memcmp(node, maximum, 255);
        CHECK(sethostname(original.nodename, strlen(original.nodename)) == 0);
        CHECK(max_ok);
    }
    CHECK(uname(&current) == 0 && !strcmp(current.nodename, original.nodename));
    puts("system-identity: PASS uname hostname manifest ABI limits faults sharing and authorization");
    return 0;
}
