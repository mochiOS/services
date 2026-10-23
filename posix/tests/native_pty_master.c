/* Run on mochiOS: master allocation, real-ID grant, unlock and native IO. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
extern int posix_openpt(int);
extern int unlockpt(int);
extern int grantpt(int);
extern int ptsname_r(int, char *, size_t);

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "pty-master: FAIL line=%d errno=%d\n", __LINE__, errno); \
        return 1; \
    } \
} while (0)

int main(void) {
    CHECK(posix_openpt(O_RDONLY) == -1 && errno == EINVAL);
    CHECK(posix_openpt(O_WRONLY) == -1 && errno == EINVAL);
    CHECK(posix_openpt(O_RDWR | O_CREAT) == -1 && errno == EINVAL);
    CHECK(grantpt(-1) == -1 && errno == EBADF);
    int master = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    CHECK(master >= 0);
    CHECK((fcntl(master, F_GETFL) & (O_ACCMODE | O_NONBLOCK)) == (O_RDWR | O_NONBLOCK));
    CHECK((fcntl(master, F_GETFD) & FD_CLOEXEC) != 0);
    char name[64];
    CHECK(ptsname_r(master, name, sizeof(name)) == 0);
    CHECK(chmod(name, 0777) == 0);
    CHECK(grantpt(master) == 0);
    struct stat metadata;
    CHECK(stat(name, &metadata) == 0);
    CHECK(metadata.st_uid == getuid() && metadata.st_gid == getgid());
    CHECK((metadata.st_mode & 07777) == 0620);
    CHECK(open(name, O_RDWR | O_NOCTTY) == -1 && errno == EIO);
    int duplicate = dup(master);
    CHECK(duplicate >= 0);
    CHECK(unlockpt(duplicate) == 0);
    int slave = open(name, O_RDWR | O_NOCTTY);
    CHECK(slave >= 0);
    CHECK(grantpt(slave) == -1 && errno == EINVAL);
    CHECK(write(master, "ok\n", 3) == 3);
    char input[3];
    CHECK(read(slave, input, sizeof(input)) == 3 && memcmp(input, "ok\n", 3) == 0);
    CHECK(unlockpt(slave) == -1 && errno == EINVAL);
    CHECK(close(master) == 0);
    CHECK(write(duplicate, "ok\n", 3) == 3);
    CHECK(read(slave, input, sizeof(input)) == 3 && memcmp(input, "ok\n", 3) == 0);
    CHECK(close(duplicate) == 0);
    CHECK(close(slave) == 0);
    fprintf(stderr, "pty-master: pass\n");
    return 0;
}
