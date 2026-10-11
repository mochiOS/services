/* Early Capability-slot ABI probe, independent of Rust std initialization. */
#include <stdint.h>
#include <stddef.h>

#ifdef FREESTANDING_PROBE
/* Test the native boundary without any libc bootstrap dependency. */
__asm__(".global _start\n_start:\n"
        "andq $-16, %rsp\ncall main\nmovl %eax, %edi\n"
        "movq $574, %rax\nsyscall\nud2\n");
#endif

struct identity { uint64_t process, thread; };
struct security_identity {
    uint64_t process, thread;
    uint8_t provenance, reserved0[7], key[32];
    uint16_t package_length, developer_length;
    uint32_t reserved1;
    uint8_t package[128], developer[128];
};
_Static_assert(sizeof(struct security_identity) == 320, "native security ABI");
_Static_assert(offsetof(struct security_identity, provenance) == 16, "no UID/GID padding");
_Static_assert(offsetof(struct security_identity, package) == 64, "native package offset");

static int64_t native3(uint64_t number, uint64_t a, uint64_t b, uint64_t c) {
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return (int64_t)number;
}
#define LINE_TEXT_IMPL(line) #line
#define LINE_TEXT(line) LINE_TEXT_IMPL(line)
#define CHECK(condition) do { \
    if (!(condition)) { \
        static const char fail[] = "native-security: FAIL line " LINE_TEXT(__LINE__) "\n"; \
        native3(660, (uint64_t)fail, sizeof(fail) - 1, 0); \
        return 1; \
    } \
} while (0)

int main(void) {
    static const char start[] = "native-security: start\n";
    native3(660, (uint64_t)start, sizeof(start) - 1, 0);
    struct identity caller = {0};
    CHECK(native3(677, (uint64_t)&caller, sizeof(caller), 0) == 0);
    static struct { struct security_identity record; uint64_t guard; } output;
    unsigned char *bytes = (unsigned char *)&output;
    for (unsigned i = 0; i < sizeof(output); ++i) bytes[i] = 0x5a;
    CHECK(native3(617, 0, (uint64_t)&output.record, 319) == -22);
    for (unsigned i = 0; i < sizeof(output); ++i) CHECK(bytes[i] == 0x5a);
    CHECK(native3(617, 0, 0, 320) == -14);
    CHECK(native3(617, 0, (uint64_t)&output.record, 320) == 0);
    CHECK(output.guard == UINT64_C(0x5a5a5a5a5a5a5a5a));
    CHECK(output.record.process == caller.process && output.record.thread == caller.thread);
    CHECK(output.record.provenance == 1);
    static const char package[] = "org.mochios.capability";
    CHECK(output.record.package_length == sizeof(package) - 1);
    for (unsigned i = 0; i < sizeof(package) - 1; ++i)
        CHECK(output.record.package[i] == (unsigned char)package[i]);
    int64_t endpoint = native3(587, 0, 0, 0);
    CHECK(endpoint > 0);
    CHECK(native3(617, endpoint, (uint64_t)&output.record, 320) == 0);
    CHECK(output.record.process == caller.process && output.record.thread == caller.thread);
    CHECK(native3(617, UINT64_MAX, (uint64_t)&output.record, 320) == -22);
    static const char pass[] = "native-security: PASS exact-size credential-free ABI, "
                               "caller and endpoint identity, package provenance, invalid output\n";
    native3(660, (uint64_t)pass, sizeof(pass) - 1, 0);
    return 0;
}
