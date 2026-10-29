/* Resolver/TLS/constructor ordering fixture; all policy remains in userspace. */
#include <stdio.h>
#include <unistd.h>
extern int native_root_value;
extern int native_root_fini;
static __thread int seed = 17;
static int calls;
static int constructor_value;
static int constructor_started;
static int late_resolution;
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
int native_pointer_call(void) { return selected_pointer(); }
int native_local_call(void) { return local_pointer(); }
int native_resolver_count(void) { return calls; }
int native_constructor_value(void) { return constructor_value; }
int native_late_resolution(void) { return late_resolution; }
void native_set_seed(int value) { seed = value; }
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
