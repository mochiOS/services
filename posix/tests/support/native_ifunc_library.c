/* Resolver/TLS/constructor ordering fixture; all policy remains in userspace. */
#include <stdio.h>
#include <unistd.h>
#ifdef RELRO_PROBE
#include <errno.h>
#endif
extern int native_root_value;
extern int native_root_fini;
static __thread int seed = 17;
static int calls;
static int constructor_value;
static int constructor_started;
static int late_resolution;
static int late_constructor;
static int lifecycle_resolvers;
#ifdef LARGE_METADATA
static int large_initializers;
static int large_finalizers;
static void large_initialize(void) __attribute__((used));
static void large_initialize(void) { ++large_initializers; }
static void large_finalize(void) __attribute__((used));
static void large_finalize(void) { ++large_finalizers; }
int native_large_initializers(void) { return large_initializers; }
__asm__(".section .data,\"aw\"\n.rept 200\n.quad native_pick\n.endr\n"
        ".section .init_array,\"aw\"\n.rept 640\n.quad large_initialize\n.endr\n.text\n");
#endif
static int implementation(void) { return seed + native_root_value + 35; }
static int bad_implementation(void) { return -1; }
static int (*select_implementation(void))(void) __attribute__((used));
static int (*select_implementation(void))(void) {
    ++calls;
    if (constructor_started) late_resolution = 1;
    return seed == 17 && native_root_value == 21 ? implementation : bad_implementation;
}
/* The bare-metal GCC frontend rejects the ifunc attribute, while its GNU
 * assembler/linker support STT_GNU_IFUNC. Emit that exact ELF symbol type. */
int native_pick(void);
__asm__(".globl native_pick\n.type native_pick,@gnu_indirect_function\n"
        ".set native_pick,select_implementation\n");
int native_local_pick(void);
__asm__(".local native_local_pick\n.type native_local_pick,@gnu_indirect_function\n"
        ".set native_local_pick,select_implementation\n");
static int (*volatile selected_pointer)(void) = native_pick;
static int (*volatile local_pointer)(void) = native_local_pick;
int (*native_copied_pointer)(void) = native_pick;
void *native_copy_address(void) { return &native_copied_pointer; }
int native_pointer_call(void) { return selected_pointer(); }
int native_local_call(void) { return local_pointer(); }
int native_resolver_count(void) { return calls; }
int native_constructor_value(void) { return constructor_value; }
int native_late_resolution(void) { return late_resolution; }
void native_set_seed(int value) { seed = value; }
int native_late_constructor(void) { return late_constructor; }
int native_lifecycle_resolvers(void) { return lifecycle_resolvers; }
extern void (*native_late_fini_slot)(void);
static void late_initialize(void) {
    if (seed != 17 || native_root_value != 21 || lifecycle_resolvers != 2) _exit(2);
    late_constructor = 1;
    /* The CRT must have frozen the finalizer before the first constructor. */
#ifdef RELRO_PROBE
    /* Faultable POSIX read must reject this destination before constructors
     * can mutate a RELRO finalizer. It must leave the pipe byte available. */
    int fds[2];
    char byte = 1, received = 0;
    if (pipe(fds) || write(fds[1], &byte, 1) != 1) _exit(7);
    errno = 0;
    if (read(fds[0], &native_late_fini_slot, 1) != -1 || errno != EFAULT) _exit(8);
    if (read(fds[0], &received, 1) != 1 || received != byte) _exit(9);
    if (close(fds[0]) || close(fds[1])) _exit(10);
    puts("relro-native: protected before constructor PASS");
#else
    native_late_fini_slot = 0;
#endif
}
static void late_finalize(void) {
    if (!native_root_fini || !late_constructor || lifecycle_resolvers != 2) _exit(3);
#ifdef LARGE_METADATA
    if (large_initializers != 640 || large_finalizers != 640) _exit(6);
#endif
    puts("indirect-native: captured IFUNC fini PASS");
}
static void (*select_initialize(void))(void) __attribute__((used));
static void (*select_initialize(void))(void) {
    if (seed != 17 || native_root_value != 21 || constructor_started || late_constructor) _exit(4);
    ++lifecycle_resolvers;
    return late_initialize;
}
static void (*select_finalize(void))(void) __attribute__((used));
static void (*select_finalize(void))(void) {
    if (seed != 17 || native_root_value != 21 || constructor_started || late_constructor) _exit(5);
    ++lifecycle_resolvers;
    return late_finalize;
}
__asm__(".local late_init_pick\n.type late_init_pick,@gnu_indirect_function\n"
        ".set late_init_pick,select_initialize\n"
        ".local late_fini_pick\n.type late_fini_pick,@gnu_indirect_function\n"
        ".set late_fini_pick,select_finalize\n"
        ".section .init_array,\"aw\"\n.quad late_init_pick\n"
        ".section .fini_array,\"aw\"\n.globl native_late_fini_slot\n"
        ".hidden native_late_fini_slot\nnative_late_fini_slot: .quad late_fini_pick\n.text\n");
#ifdef LARGE_METADATA
__asm__(".section .fini_array,\"aw\"\n.rept 640\n.quad large_finalize\n.endr\n.text\n");
#endif
static void initialize(void) __attribute__((constructor));
static void initialize(void) {
    constructor_started = 1;
    constructor_value = native_pick() + native_local_call();
}
static void finalize(void) __attribute__((destructor));
static void finalize(void) {
    if (!native_root_fini || native_late_resolution()) _exit(1);
    puts("indirect-native: fini PASS");
}
