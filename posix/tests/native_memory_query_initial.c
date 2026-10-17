/* Native IPC provider probe, independent of libc and POSIX services. */
#include <stdint.h>
#include <stdatomic.h>

enum { THREAD_CREATE = 577, YIELD = 579, MEMORY_MAP = 582,
       ENDPOINT_CREATE = 629, RECEIVE = 631, REPLY = 633,
       PROVIDER_CREATE = 637, DEBUG = 660, READ_AT = 673 };
struct attachment { uint32_t handle, reserved; uint64_t rights; };
struct attachments { uint32_t count, flags; struct attachment items[4]; };
struct thread_context {
    uint64_t entry, stack, argument, tls, flags, reserved[3], registers[14];
};
_Static_assert(sizeof(struct thread_context) == 176, "ThreadCreateContext ABI");
static _Alignas(16) unsigned char worker_stack[16384];
static _Atomic uint64_t objects[3];
static _Atomic unsigned queries[3];

static int64_t native(uint64_t number, uint64_t a, uint64_t b, uint64_t c,
                      uint64_t d, uint64_t e, uint64_t f) {
    register uint64_t r10 __asm__("r10") = d;
    register uint64_t r8 __asm__("r8") = e;
    register uint64_t r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "+a"(number)
        : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return (int64_t)number;
}
static void text(const char *s) {
    uint64_t length = 0;
    while (s[length]) ++length;
    native(DEBUG, (uintptr_t)s, length, 0, 0, 0, 0);
}
__attribute__((noreturn)) static void fail(unsigned line, int64_t result) {
    const char digits[] = "0123456789abcdef";
    char message[] = "memory-query-initial: FAIL line=0000 result=0000000000000000\n";
    for (unsigned i = 0; i < 4; ++i)
        message[sizeof("memory-query-initial: FAIL line=")+2-i] = digits[(line >> (4*i)) & 15];
    for (unsigned i = 0; i < 16; ++i)
        message[sizeof(message)-3-i] = digits[((uint64_t)result >> (4*i)) & 15];
    text(message);
    for (;;) native(YIELD, 0, 0, 0, 0, 0, 0);
}
#define CHECK(expression, expected) do { \
    int64_t result = (expression); \
    if (result != (expected)) fail(__LINE__, result); \
} while (0)
static uint64_t get64(const unsigned char *p) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= (uint64_t)p[i] << (8*i);
    return value;
}
static void put64(unsigned char *p, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) p[i] = (unsigned char)(value >> (8*i));
}
__attribute__((noreturn)) static void provider(void) {
    int64_t endpoint = native(ENDPOINT_CREATE, 0, 0, 0, 0, 0, 0);
    if (endpoint <= 0) fail(__LINE__, endpoint);
    for (unsigned i = 0; i < 3; ++i) {
        int64_t handle = native(PROVIDER_CREATE, endpoint, i+1, 1|64, 0, 0, 0);
        if (handle <= 0) fail(__LINE__, handle);
        atomic_store_explicit(&objects[i], handle, memory_order_release);
    }
    for (;;) {
        unsigned char request[48], response[41] = {0};
        struct attachments incoming = {0}, outgoing = {0};
        int64_t received = native(RECEIVE, (uintptr_t)request, sizeof(request),
                                  (uintptr_t)&incoming, endpoint, 0, 0);
        if (received < 0 || (uint32_t)received != 48 || incoming.count || incoming.flags != 1)
            fail(__LINE__, received);
        uint64_t object = get64(request+8);
        if (object < 1 || object > 3) fail(__LINE__, object);
        unsigned opcode = request[6] | (unsigned)request[7] << 8;
        for (unsigned i = 0; i < 8; ++i) response[i] = request[i];
        put64(response+16, object);
        unsigned length = 40;
        if (opcode == 9) {
            unsigned count = atomic_fetch_add_explicit(&queries[object-1], 1, memory_order_release);
            if (object == 2) put64(response+24, 77);
            if (object == 3 && count < 2) put64(response+8, (uint64_t)(count ? -38 : -95));
        } else if (opcode == 6) {
            put64(response+24, 1);
            response[32] = 1;
            response[40] = 'A';
            length = 41;
        } else fail(__LINE__, opcode);
        CHECK(native(REPLY, (uint64_t)received >> 32, (uintptr_t)response,
                     length, (uintptr_t)&outgoing, 0, 0), 0);
    }
}
__attribute__((used, noreturn)) static void probe_main(void) {
    text("memory-query-initial: start\n");
    struct thread_context context = {0};
    context.entry = (uintptr_t)provider;
    context.stack = (uintptr_t)(worker_stack+sizeof(worker_stack)-8);
    int64_t thread = native(THREAD_CREATE, (uintptr_t)&context, sizeof(context), 0, 0, 0, 0);
    if (thread <= 0) fail(__LINE__, thread);
    while (!atomic_load_explicit(&objects[2], memory_order_acquire))
        native(YIELD, 0, 0, 0, 0, 0, 0);
    unsigned char byte = 0;
    for (unsigned i = 0; i < 2; ++i) {
        for (unsigned repeat = 0; repeat < 2; ++repeat) {
            CHECK(native(READ_AT, objects[i], (uintptr_t)&byte, 1, 0, 0, 0), 1);
            if (byte != 'A') fail(__LINE__, byte);
        }
        CHECK(atomic_load_explicit(&queries[i], memory_order_acquire), 1);
    }
    CHECK(native(MEMORY_MAP, 0, 4096, 1, 0, objects[0], 0), -262139);
    CHECK(atomic_load_explicit(&queries[0], memory_order_acquire), 1);
    CHECK(native(READ_AT, objects[2], (uintptr_t)&byte, 1, 0, 0, 0), -95);
    CHECK(native(READ_AT, objects[2], (uintptr_t)&byte, 1, 0, 0, 0), -38);
    CHECK(native(READ_AT, objects[2], (uintptr_t)&byte, 1, 0, 0, 0), 1);
    CHECK(native(READ_AT, objects[2], (uintptr_t)&byte, 1, 0, 0, 0), 1);
    CHECK(atomic_load_explicit(&queries[2], memory_order_acquire), 3);
    text("memory-query-initial: PASS explicit absent/present backing, cached success, opaque errors, retry and mapping rejection\n");
    for (;;) native(YIELD, 0, 0, 0, 0, 0, 0);
}
__attribute__((naked, noreturn, section(".text._start"))) void _start(void) {
    __asm__ volatile("andq $-16, %rsp\n\tcall probe_main\n\tud2");
}
