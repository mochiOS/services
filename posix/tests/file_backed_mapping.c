#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Run with the target runtime and an inherited POSIX endpoint. */
int main(void) {
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) return 1;
    size_t page = (size_t)page_size;
    char path[] = "/tmp/posix-pager-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return 2;
    unsigned char *seed = malloc(page * 2);
    if (!seed) return 3;
    memset(seed, 0x11, page);
    memset(seed + page, 0x22, page);
    if (write(fd, seed, page * 2) != (ssize_t)(page * 2)) return 4;
    if (lseek(fd, 19, SEEK_SET) != 19) return 5;

    unsigned char *shared = mmap(0, page, PROT_READ | PROT_WRITE,
                                 MAP_SHARED, fd, (off_t)page);
    if (shared == MAP_FAILED || shared[0] != 0x22) return 6;
    if (lseek(fd, 0, SEEK_CUR) != 19) return 7;
    shared[37] = 0x77;
    if (msync(shared, page, MS_SYNC) != 0) return 8;
    if (lseek(fd, (off_t)page + 37, SEEK_SET) != (off_t)page + 37) return 9;
    unsigned char observed = 0;
    if (read(fd, &observed, 1) != 1 || observed != 0x77) return 10;

    int read_only = open(path, O_RDONLY);
    if (read_only < 0) return 11;
    unsigned char *restricted = mmap(0, page, PROT_READ, MAP_SHARED,
                                     read_only, (off_t)page);
    if (restricted == MAP_FAILED || restricted[37] != 0x77) return 12;
    errno = 0;
    if (mprotect(restricted, page, PROT_READ | PROT_WRITE) != -1 ||
        errno != EACCES) return 13;
    unsigned char *private = mmap(0, page, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE, read_only, (off_t)page);
    if (private == MAP_FAILED) return 14;
    private[37] = 0x99;
    if (msync(private, page, MS_SYNC) != 0 || shared[37] != 0x77) return 15;

    /* Neither pathname nor descriptor lifetime determines mapping lifetime. */
    if (unlink(path) != 0 || close(read_only) != 0 || close(fd) != 0) return 16;
    if (restricted[37] != 0x77 || private[37] != 0x99) return 17;
    shared[38] = 0x88;
    if (msync(shared, page, MS_SYNC) != 0 || restricted[38] != 0x88) return 18;
    if (munmap(private, page) != 0 || munmap(restricted, page) != 0 ||
        munmap(shared, page) != 0) return 19;
    free(seed);
    puts("file-backed mapping: ok");
    return 0;
}
