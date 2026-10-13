#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

/* Existing runtime entry point; this SDK lacks the sys/random.h wrapper. */
extern ssize_t getrandom(void *, size_t, unsigned int);

static int check(void) {
    volatile unsigned char *page = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                                        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return 1;
    page[0] = 31;
    for (unsigned mode = 0; mode < 2; ++mode) {
        pid_t child = fork();
        if (child < 0) return 2;
        if (!child) {
            if (mprotect((void *)page, 4096, mode ? PROT_READ|PROT_EXEC : PROT_READ)) _exit(2);
            errno = 0;
            if (getrandom((void *)page, 1, 0) != -1 || errno != EFAULT) _exit(3);
            page[0] = 99; /* Must fault, never regain write merely through COW. */
            _exit(0);
        }
        int status = 0;
        if (waitpid(child, &status, 0) != child || status == 0 || status == (2 << 8) || status == (3 << 8)) return 3;
        if (page[0] != 31) return 4;
    }
    pid_t child = fork();
    if (child < 0) return 5;
    if (!child) {
        if (mprotect((void *)page, 4096, PROT_READ)) _exit(1);
        if (mprotect((void *)page, 4096, PROT_READ|PROT_WRITE)) _exit(2);
        page[0] = 77;
        _exit(page[0] != 77);
    }
    int status = -1;
    if (waitpid(child, &status, 0) != child || status || page[0] != 31) return 6;
    /* A page made inaccessible before fork must retain its bytes and private
       ownership, not disappear from the captured image or become zero-fill. */
    if (mprotect((void *)page, 4096, PROT_NONE)) return 8;
    child = fork();
    if (child < 0) return 9;
    if (!child) {
        if (mprotect((void *)page, 4096, PROT_READ|PROT_WRITE) || page[0] != 31) _exit(1);
        page[0] = 55;
        _exit(0);
    }
    if (waitpid(child, &status, 0) != child || status) return 10;
    if (mprotect((void *)page, 4096, PROT_READ|PROT_WRITE) || page[0] != 31) return 11;
    if (mprotect((void *)page, 4096, PROT_READ)) return 12;
    child = fork();
    if (child < 0) return 13;
    if (!child) {
        if (mprotect((void *)page, 4096, PROT_READ|PROT_WRITE)) _exit(1);
        page[0] = 66;
        _exit(0);
    }
    if (waitpid(child, &status, 0) != child || status || page[0] != 31) return 14;
    if (munmap((void *)page, 4096)) return 7;
    return 0;
}

int main(void) {
    int result = check();
    fprintf(stderr, "cow-readonly: %s read/RX writes denied, RW regrant isolated result=%d\n",
            result ? "FAIL" : "PASS", result);
    return result;
}
