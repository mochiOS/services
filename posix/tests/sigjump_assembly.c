#include <assert.h>
#include <stdint.h>
#include <stdatomic.h>

typedef uint64_t buffer_t[15];
extern int sigsetjmp(buffer_t, int) __attribute__((returns_twice));
extern void __mochios_sigjump_restore(const uint64_t *, int, atomic_uint *, unsigned)
    __attribute__((noreturn));
static unsigned calls;
static atomic_uint deferred;
extern int sigjump_probe(atomic_uint *);
void __mochios_sigsetjmp_prepare(uint64_t *buffer, int mask) {
    assert(mask == 37);
    assert(buffer[6] && buffer[7] && !(buffer[6] & 15));
    for (unsigned i = 8; i < 15; ++i) buffer[i] = 0x2000 + i;
    ++calls;
}
static void jump(buffer_t buffer, int value) {
    atomic_store_explicit(&deferred, 7, memory_order_release);
    __mochios_sigjump_restore(buffer, value, &deferred, 3);
}
int main(void) {
    for (volatile int i = 0; i < 3; ++i) {
        buffer_t buffer;
        volatile uint64_t preserved[4] = {0x11335577, 0x22446688, 0xdeadbeef, 0xabcdef};
        int value = sigsetjmp(buffer, 37);
        if (!value) jump(buffer, i == 0 ? 0 : i == 1 ? 37 : -7);
        assert(value == (i == 0 ? 1 : i == 1 ? 37 : -7));
        assert(atomic_load_explicit(&deferred, memory_order_acquire) == 3);
        assert(preserved[0] == 0x11335577 && preserved[1] == 0x22446688
            && preserved[2] == 0xdeadbeef && preserved[3] == 0xabcdef);
        for (unsigned field = 8; field < 15; ++field) assert(buffer[field] == 0x2000 + field);
    }
    assert(calls == 3);
    atomic_store_explicit(&deferred, 7, memory_order_release);
    assert(sigjump_probe(&deferred) == 37);
    assert(calls == 4 && atomic_load_explicit(&deferred, memory_order_acquire) == 3);
    return 0;
}
