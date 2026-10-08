#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

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
    puts("heap mapping isolation: ok");
    return 0;
}
