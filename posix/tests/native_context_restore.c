#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

enum { INSTALL = 654, RETURN = 655, THREAD = 656, INTERRUPT = 657,
       INSPECT = 688, RESTORE = 690 };
struct snapshot {
    uint64_t instruction, stack_pointer, flags, argument;
    struct { uint64_t rax, rbx, rcx, rdx, rsi, rbp, r8, r9, r10, r11, r12, r13, r14, r15; } registers;
    unsigned char fx_state[512];
} __attribute__((aligned(16)));
_Static_assert(sizeof(struct snapshot) == 656, "native CPU context ABI");
struct snapshot selected, observed;
static unsigned char callback_stack[16384] __attribute__((aligned(4096)));
static volatile int callback_seen;
extern int context_probe(void);
extern void context_landing(void);

static inline uint64_t native(uint64_t number, uint64_t a, uint64_t b, uint64_t c) {
    __asm__ volatile("syscall" : "+a"(number) : "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return number;
}
#define CHECK(test) do { if (!(test)) { fprintf(stderr, "context-restore: FAIL line=%d\n", __LINE__); return 1; } } while (0)

/* Capture every restored GPR before using scratch registers. Neither the
   syscall nor its IRET may write to the destination's 128-byte red zone. */
__asm__(
".text\n.global context_probe\n.type context_probe,@function\ncontext_probe:\n"
"push %rbx\npush %rbp\npush %r12\npush %r13\npush %r14\npush %r15\n"
"mov %rsp, selected+8(%rip)\n"
"lea -128(%rsp), %rdi\nmov $16,%ecx\nmov $0x5a,%eax\nrep stosq\n"
"lea selected(%rip),%rdi\nmov $656,%esi\nmov $690,%eax\nsyscall\n"
"mov $-1,%eax\njmp context_done\n"
".global context_landing\ncontext_landing:\n"
"mov %rdi,observed+24(%rip)\nmov %rax,observed+32(%rip)\n"
"mov %rbx,observed+40(%rip)\nmov %rcx,observed+48(%rip)\n"
"mov %rdx,observed+56(%rip)\nmov %rsi,observed+64(%rip)\n"
"mov %rbp,observed+72(%rip)\nmov %r8,observed+80(%rip)\n"
"mov %r9,observed+88(%rip)\nmov %r10,observed+96(%rip)\n"
"mov %r11,observed+104(%rip)\nmov %r12,observed+112(%rip)\n"
"mov %r13,observed+120(%rip)\nmov %r14,observed+128(%rip)\n"
"mov %r15,observed+136(%rip)\nmov %rsp,observed+8(%rip)\n"
"fxsave64 observed+144(%rip)\n"
"lea -128(%rsp),%rdi\nmov $16,%ecx\nmov $0x5a,%eax\nrepe scasq\n"
"jne context_bad_redzone\nmov $42,%eax\njmp context_done\n"
"context_bad_redzone:\nmov $-2,%eax\n"
"context_done:\npop %r15\npop %r14\npop %r13\npop %r12\npop %rbp\npop %rbx\nret\n"
".size context_probe,.-context_probe\n"
);

static void handler(uint64_t payload, uint64_t token) {
    struct snapshot before, after;
    if (payload != 0x55 || native(INSPECT, token, (uintptr_t)&before, sizeof(before))
        || (int64_t)native(RESTORE, (uintptr_t)&selected, sizeof(selected), 0) != -11
        || native(INSPECT, token, (uintptr_t)&after, sizeof(after))
        || memcmp(&before, &after, sizeof(before))) _exit(91);
    callback_seen = 1;
    native(RETURN, token, 0, 0);
    _exit(92);
}

int main(void) {
    __asm__ volatile("fxsave64 %0" : "=m"(selected.fx_state));
    selected.instruction = (uintptr_t)context_landing;
    selected.stack_pointer = (uintptr_t)callback_stack + sizeof(callback_stack);
    selected.flags = 0x202;
    selected.argument = 0xdead;
    uint64_t *registers = (uint64_t *)&selected.registers;
    for (unsigned i = 0; i < 14; ++i) registers[i] = UINT64_C(0x1234567800000000) + i;
    struct snapshot invalid = selected;
    CHECK((int64_t)native(RESTORE, 0, sizeof(selected), 0) == -22);
    CHECK((int64_t)native(RESTORE, 1, sizeof(selected), 0) == -14);
    CHECK((int64_t)native(RESTORE, (uintptr_t)&selected, sizeof(selected) - 1, 0) == -22);
    invalid.flags |= 3u << 12;
    CHECK((int64_t)native(RESTORE, (uintptr_t)&invalid, sizeof(invalid), 0) == -22);
    invalid = selected; invalid.stack_pointer = 0;
    CHECK((int64_t)native(RESTORE, (uintptr_t)&invalid, sizeof(invalid), 0) == -22);
    invalid = selected; invalid.instruction = UINT64_C(0xffff800000000000);
    CHECK((int64_t)native(RESTORE, (uintptr_t)&invalid, sizeof(invalid), 0) == -22);
    invalid = selected; invalid.stack_pointer = UINT64_C(0xffff800000000000);
    CHECK((int64_t)native(RESTORE, (uintptr_t)&invalid, sizeof(invalid), 0) == -22);
    invalid = selected;
    invalid.fx_state[27] = 0x80;
    memset(invalid.fx_state + 28, 0xff, 4);
    CHECK((int64_t)native(RESTORE, (uintptr_t)&invalid, sizeof(invalid), 0) == -22);
    struct { uint64_t entry, base, size, flags, reserved[4]; } config = {
        (uintptr_t)handler, (uintptr_t)callback_stack, sizeof(callback_stack), 0, {0}
    };
    CHECK(native(INSTALL, (uintptr_t)&config, sizeof(config), 0) == 0);
    uint64_t thread = native(THREAD, 0, 0, 0);
    CHECK((int64_t)thread > 0);
    CHECK(native(INTERRUPT, thread, 0x55, 0) == 0 && callback_seen == 1);
    unsigned old_mxcsr;
    __asm__ volatile("stmxcsr %0" : "=m"(old_mxcsr));
    unsigned changed_mxcsr = (old_mxcsr & ~0x6000u) | 0x4000u;
    memcpy(selected.fx_state + 24, &changed_mxcsr, 4);
    memset(selected.fx_state + 160, 0x5b, 16);
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        int result = context_probe();
        __asm__ volatile("ldmxcsr %0" : : "m"(old_mxcsr));
        CHECK(result == 42);
        CHECK(observed.stack_pointer == selected.stack_pointer && observed.argument == selected.argument);
        CHECK(!memcmp(&observed.registers, &selected.registers, sizeof(selected.registers)));
        CHECK(!memcmp(observed.fx_state + 24, &changed_mxcsr, 4));
        CHECK(!memcmp(observed.fx_state + 160, selected.fx_state + 160, 16));
    }
    puts("context-restore: PASS validated self continuation, full GPR/FX, red zone, repeated use and active-token rejection");
    return 0;
}
