#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

/* Separate address spaces must be able to populate reserved pages at once.
 * Threads in one process alone would not exercise a shared kernel scratch VA. */
static int populate_reserved_pages(unsigned char value) {
    const size_t size = 1024 * 1024;
    for (unsigned iteration = 0; iteration < 8; ++iteration) {
        unsigned char *mapping = mmap(0, size, PROT_NONE,
                                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping == MAP_FAILED) return 10;
        if (mprotect(mapping, size, PROT_READ | PROT_WRITE) != 0) return 11;
        for (size_t offset = 0; offset < size; offset += 4096) {
            if (mapping[offset] != 0) return 12;
        }
        memset(mapping, value, size);
        for (size_t offset = 0; offset < size; offset += 4096) {
            if (mapping[offset] != value) return 13;
        }
        if (munmap(mapping, size) != 0) return 14;
    }
    return 0;
}

/* The allocator's contiguous arena must survive unrelated native mappings. */
int main(void) {
    void *first = malloc(4144);
    if (!first) return 1;
    void *mapping = mmap(0, 65536, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) return 2;
    memset(mapping, 0x5a, 65536);
    unsigned char *growth = malloc(1024 * 1024);
    if (!growth) return 3;
    memset(growth, 0xa5, 1024 * 1024);
    if (growth[0] != 0xa5 || growth[1024 * 1024 - 1] != 0xa5 ||
        ((unsigned char *)mapping)[0] != 0x5a) return 4;
    free(growth);
    free(first);
    if (munmap(mapping, 65536) != 0) return 5;
    pid_t child = fork();
    if (child < 0) { perror("heap mapping: fork"); return 6; }
    if (child == 0) _exit(populate_reserved_pages(0x6b));
    int result = populate_reserved_pages(0xd3);
    int status = 0;
    if (waitpid(child, &status, 0) != child) return 7;
    if (result != 0) return result;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return 8;
    fprintf(stderr, "heap mapping isolation and concurrent population: ok\n");
    return 0;
}
