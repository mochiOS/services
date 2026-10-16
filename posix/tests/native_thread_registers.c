/* Explicit native entry state, independent of POSIX thread conventions. */
#include <stdint.h>
#include <pthread.h>

static unsigned char register_stack[65536] __attribute__((aligned(16)));
static volatile uint64_t register_result[18];
static uint64_t register_tls = UINT64_C(0xabcddcba11223344);
#define NATIVE_INVALID_ARGUMENT INT64_C(-262139)
extern void native_register_entry(void);
__asm__(
    ".text\n"
    ".type native_register_entry,@function\n"
    "native_register_entry:\n"
    "mov %rax, 0(%rdi)\n"
    "mov %rbx, 8(%rdi)\n"
    "mov %rcx, 16(%rdi)\n"
    "mov %rdx, 24(%rdi)\n"
    "mov %rsi, 32(%rdi)\n"
    "mov %rbp, 40(%rdi)\n"
    "mov %r8, 48(%rdi)\n"
    "mov %r9, 56(%rdi)\n"
    "mov %r10, 64(%rdi)\n"
    "mov %r11, 72(%rdi)\n"
    "mov %r12, 80(%rdi)\n"
    "mov %r13, 88(%rdi)\n"
    "mov %r14, 96(%rdi)\n"
    "mov %r15, 104(%rdi)\n"
    "mov %rsp, 112(%rdi)\n"
    "pushfq\n"
    "pop %rax\n"
    "mov %rax, 120(%rdi)\n"
    "mov %fs:0, %rax\n"
    "mov %rax, 128(%rdi)\n"
    "movq $1, 136(%rdi)\n"
    "mov $578, %eax\n"
    "xor %edi, %edi\n"
    "syscall\n"
    "ud2\n"
    ".size native_register_entry, .-native_register_entry\n"
);

static int64_t register_native(uint64_t number, uint64_t a, uint64_t b) {
    __asm__ volatile("syscall" : "+a"(number) : "D"(a), "S"(b)
                     : "rcx", "r11", "memory");
    return (int64_t)number;
}

static void *return_argument(void *argument) { return argument; }

int native_thread_register_probe(void) {
    struct initial_context {
        uint64_t entry, stack, argument, tls, flags, reserved[3], registers[14];
    } context = {0};
    _Static_assert(sizeof(context) == 176, "ThreadCreateContext layout");
    context.entry = (uint64_t)native_register_entry;
    context.stack = (uint64_t)(register_stack + sizeof(register_stack));
    context.argument = (uint64_t)register_result;
    context.tls = (uint64_t)&register_tls;
    for (unsigned i = 0; i < 14; ++i) {
        context.registers[i] = UINT64_C(0xdead123400000000) + i;
    }
    /* The old, shorter ABI must be rejected rather than reading past it. */
    if (register_native(577, (uint64_t)&context, 64) != NATIVE_INVALID_ARGUMENT) return 1;
    context.flags = 1;
    if (register_native(577, (uint64_t)&context, sizeof(context)) != NATIVE_INVALID_ARGUMENT) return 2;
    context.flags = 0;
    context.reserved[0] = 1;
    if (register_native(577, (uint64_t)&context, sizeof(context)) != NATIVE_INVALID_ARGUMENT) return 23;
    context.reserved[0] = 0;
    if (register_native(577, (uint64_t)&context, sizeof(context)) <= 0) return 3;
    for (unsigned i = 0; i < 1000 && !register_result[17]; ++i) {
        if (register_native(517, 1, 0) != 0) return 4;
    }
    if (!register_result[17]) return 5;
    for (unsigned i = 0; i < 14; ++i) {
        if (register_result[i] != context.registers[i]) return 6 + i;
    }
    if (register_result[14] != context.stack) return 20;
    if ((register_result[15] & UINT64_C(0x27200)) != 0x200) return 21;
    if (register_result[16] != register_tls) return 22;
    pthread_t thread;
    void *returned = NULL;
    if (pthread_create(&thread, NULL, return_argument, &register_tls) != 0) return 24;
    if (pthread_join(thread, &returned) != 0 || returned != &register_tls) return 25;
    return 0;
}
