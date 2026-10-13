/* Run the actual newlib allocator with host mapping primitives. Its symbols
 * are reentrant (_malloc_r etc.), so the host process's libc stays untouched. */
#include <errno.h>
#include <malloc.h>
#include <reent.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

extern void *__mmap(void *, size_t, int, int, int, off_t);
extern int __munmap(void *, size_t);
static unsigned maps, unmaps;
static int allocator_errno;
int *__errno(void) { return &allocator_errno; }
static size_t break_offset;
static unsigned char arena[1024 * 1024] __attribute__((aligned(4096)));

void __malloc_lock(struct _reent *context) { (void)context; }
void __malloc_unlock(struct _reent *context) { (void)context; }
void *_sbrk_r(struct _reent *context, ptrdiff_t change) {
    if (change < 0 || (size_t)change > sizeof(arena) - break_offset) {
        context->_errno = ENOMEM;
        return (void *)-1;
    }
    void *old = arena + break_offset;
    break_offset += (size_t)change;
    return old;
}
void *mmap(void *address, size_t size, int protection, int flags, int fd, off_t offset) {
    if (address || protection != (PROT_READ|PROT_WRITE) ||
        flags != (MAP_PRIVATE|MAP_ANONYMOUS) || fd != -1 || offset != 0) return (void *)-1;
    void *result = __mmap(address, size, protection, flags, fd, offset);
    if (result != MAP_FAILED) ++maps;
    return result;
}
int munmap(void *address, size_t size) {
    int result = __munmap(address, size);
    if (!result) ++unmaps;
    return result;
}

int main(void) {
    struct _reent context = {0};
    const size_t large_size = 384u * 1024u * 1024u;
#ifndef __mochios__
    /* Other newlib targets retain their original no-mmap policy. */
    return _malloc_r(&context, large_size) || maps || context._errno != ENOMEM;
#else
    for (unsigned i = 0; i < 4; ++i) {
        unsigned char *large = _malloc_r(&context, large_size);
        if (!large) return 1;
        large[0] = 7;
        large[large_size-1] = 8;
        if (large[0] != 7 || large[large_size-1] != 8) return 2;
        _free_r(&context, large);
    }
    if (maps != 4 || unmaps != 4 || break_offset != 0) return 3;
    unsigned char *small = _malloc_r(&context, 48);
    if (!small || !break_offset || maps != 4) return 4;
    _free_r(&context, small);
    unsigned char *data = _calloc_r(&context, 1024 * 1024, 1);
    if (!data) return 5;
    for (size_t i = 0; i < 1024 * 1024; ++i) if (data[i]) return 6;
    memset(data, 0x5a, 1024 * 1024);
    data = _realloc_r(&context, data, 2 * 1024 * 1024);
    if (!data) return 7;
    for (size_t i = 0; i < 1024 * 1024; ++i) if (data[i] != 0x5a) return 8;
    _free_r(&context, data);
    void *aligned = _memalign_r(&context, 16384, 1024 * 1024);
    if (!aligned || (uintptr_t)aligned % 16384) return 9;
    _free_r(&context, aligned);
    if (maps != unmaps) return 10;
    if (_malloc_r(&context, SIZE_MAX) || context._errno != ENOMEM) return 11;
    return 0;
#endif
}
