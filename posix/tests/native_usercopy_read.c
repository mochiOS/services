#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

static volatile unsigned char *page;
static int stopped;
static int started;
static int worker_error;

static void *change_mapping(void *unused) {
    (void)unused;
    while (!__atomic_load_n(&started, __ATOMIC_ACQUIRE)) { }
    for (unsigned i = 0; i < 300; ++i) {
        if (mprotect((void *)page, 4096, PROT_NONE)
            || munmap((void *)page, 4096)) { worker_error = 1; break; }
        void *mapped = mmap((void *)page, 4096, PROT_READ|PROT_WRITE,
            MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
        if (mapped != (void *)page) { worker_error = 2; break; }
        page[0] = 0x71;
        if (mprotect((void *)page, 4096, PROT_READ)) { worker_error = 3; break; }
    }
    __atomic_store_n(&stopped, 1, __ATOMIC_RELEASE);
    return NULL;
}

int main(void) {
    int descriptors[2];
    page = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED || pipe(descriptors)) return 1;
    page[0] = 0x71;
    if (mprotect((void *)page, 4096, PROT_READ)) return 2;
    pthread_t thread;
    if (pthread_create(&thread, NULL, change_mapping, NULL)) return 3;
    unsigned copied = 0, rejected = 0;
    __atomic_store_n(&started, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&stopped, __ATOMIC_ACQUIRE)) {
        ssize_t result = write(descriptors[1], (const void *)page, 1);
        if (result == 1) {
            unsigned char byte = 0xff;
            if (read(descriptors[0], &byte, 1) != 1 || (byte != 0 && byte != 0x71)) return 4;
            ++copied;
        } else if (result == -1 && errno == EFAULT) {
            ++rejected;
        } else {
            fprintf(stderr, "usercopy-read: FAIL write=%ld errno=%d\n", (long)result, errno);
            return 5;
        }
    }
    if (pthread_join(thread, NULL) || worker_error) return 6;
    if (!copied && !rejected) return 9;
    unsigned char byte = 0;
    if (write(descriptors[1], (const void *)page, 1) != 1
        || read(descriptors[0], &byte, 1) != 1 || byte != 0x71) return 7;
    if (munmap((void *)page, 4096) || close(descriptors[0]) || close(descriptors[1])) return 8;
    fprintf(stderr, "usercopy-read: PASS concurrent protection/unmap/remap, copied=%u rejected=%u\n",
            copied, rejected);
    return 0;
}
