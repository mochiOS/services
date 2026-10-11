#include <errno.h>
#include <stdio.h>
#include <unistd.h>

/* Isolated early-boot Input replacement: original manifest and POSIX endpoint.
 * Tests the actual newlib ABI and service IPC, not desktop readiness. */
int main(void) {
    const uid_t keep_uid = (uid_t)-1;
    const gid_t keep_gid = (gid_t)-1;
    fprintf(stderr, "native-credentials: start\n");
    if (getuid() != 0 || geteuid() != 0) return 1;
    errno = 123;
    if (setreuid(keep_uid, keep_uid) || errno != 123) return 2;
    if (setregid(20, 42) || getgid() != 20 || getegid() != 42) return 3;
    if (setreuid(501, 502) || getuid() != 501 || geteuid() != 502) return 4;
    errno = 0;
    if (setreuid(502, 777) != -1 || errno != EPERM) return 5;
    if (getuid() != 501 || geteuid() != 502) return 6;
    errno = 0;
    if (setregid(42, 777) != -1 || errno != EPERM) return 7;
    if (getgid() != 20 || getegid() != 42) return 8;
    if (setreuid(keep_uid, 501) || setreuid(keep_uid, 502)) return 9;
    if (setregid(keep_gid, 20) || setregid(keep_gid, 42)) return 10;
    if (setregid(20, 20) || setreuid(501, 501)) return 11;
    errno = 0;
    if (setreuid(keep_uid, 502) != -1 || errno != EPERM) return 12;
    errno = 0;
    if (setregid(keep_gid, 42) != -1 || errno != EPERM) return 13;
    fprintf(stderr, "native-credentials: PASS atomic updates, saved IDs, ABI sentinel, errno\n");
    return 0;
}
