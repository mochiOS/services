/* Seed opaque LaunchContext keys before the real newlib runtime starts.
 * A read-only native reference is intentionally associated with two FD keys.
 * No DUPLICATE/TRANSFER authority is available on that inherited reference. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

enum { EXIT = 574, CLOSE = 626, DUPLICATE = 627, PAIR = 649,
       SET_HANDLE = 648, DEBUG = 660, SET_VALUE = 662, RIGHTS = 664,
       STREAM_WRITE = 675 };
static uint32_t reader, writer;
static int64_t native(uint64_t number, uint64_t a, uint64_t b, uint64_t c,
                      uint64_t d) {
    register uint64_t r10 __asm__("r10") = d;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a), "S"(b), "d"(c), "r"(r10)
                     : "rcx", "r11", "memory");
    return (int64_t)number;
}
static void setup_fail(void) {
    static const char message[] = "fd-launch-alias: setup failed\n";
    native(DEBUG, (uintptr_t)message, sizeof(message) - 1, 0, 0);
    native(EXIT, 91, 0, 0, 0);
    __builtin_trap();
}
#define SETUP(x) do { if (!(x)) setup_fail(); } while (0)
static void seed_fd(unsigned fd, unsigned kind, unsigned flags, uint32_t handle) {
    uint64_t metadata = (UINT64_C(0x5046) << 48) | ((uint64_t)kind << 40) | flags;
    SETUP(native(SET_VALUE, UINT64_C(0x504f534600000000) | fd, metadata, 0, 0) == 0);
    if (handle)
        SETUP(native(SET_HANDLE, UINT64_C(0x504f534800000000) | fd, handle, 0, 0) == 0);
}
__attribute__((used, noinline)) static void alias_setup(void) {
    uint32_t pair[2] = {0};
    SETUP(native(PAIR, (uintptr_t)pair, 0, 0, 0) == 0);
    int64_t limited = native(DUPLICATE, pair[0], 1, 0, 0);
    SETUP(limited > 0 && limited <= UINT32_MAX);
    reader = (uint32_t)limited;
    writer = pair[1];
    SETUP(native(CLOSE, pair[0], 0, 0, 0) == 0);
    SETUP(native(RIGHTS, reader, 0, 0, 0) == 1);
    seed_fd(1, 2, 1, 0); /* stdout */
    seed_fd(2, 3, 1, 0); /* stderr */
    seed_fd(3, 7, 0, reader);
    seed_fd(4, 7, 0, reader);
    seed_fd(5, 8, 1, writer);
    SETUP(native(SET_VALUE, UINT64_C(0x4254444658534f50), 1, 0, 0) == 0);
}
#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "fd-launch-alias: FAIL line=%d errno=%d: %s\n", __LINE__, errno, #x); \
    return 1; } } while (0)
int main(void) {
    CHECK(native(RIGHTS, reader, 0, 0, 0) == 1);
    CHECK(write(5, "AB", 2) == 2);
    char byte = 0;
    CHECK(read(3, &byte, 1) == 1 && byte == 'A');
    CHECK(close(3) == 0);
    CHECK(native(RIGHTS, reader, 0, 0, 0) == 1);
    CHECK(read(4, &byte, 1) == 1 && byte == 'B');
    CHECK(close(4) == 0);
    CHECK(native(RIGHTS, reader, 0, 0, 0) == INT64_C(-262139));
    CHECK(native(STREAM_WRITE, writer, (uintptr_t)"x", 1, 0) == INT64_C(-262134));
    CHECK(close(5) == 0);
    puts("fd-launch-alias: PASS shared inherited label, read-only rights, surviving alias, one final close and peer lifetime");
    return 0;
}
__attribute__((naked, noreturn, section(".text._start"))) void _start(void) {
    __asm__ volatile("xorq %rbp, %rbp\n\tmovq %rsp, %r12\n\tandq $-16, %rsp\n\t"
                     "call alias_setup\n\tmovq %r12, %rdi\n\tcall _start_c\n\tud2");
}
