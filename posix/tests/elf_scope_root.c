extern int shared_value;
extern int shared_function(int);
extern int optional_value __attribute__((weak));
int root_override = 41;
int *root_shared_pointer = &shared_value;
int *root_weak_pointer = &optional_value;
int (*root_function_pointer)(int) = shared_function;
void _start(void) { root_override = shared_function(shared_value); }
#ifdef MOCHIOS_RELRO_RUNTIME
unsigned long __mochios_relro_v1(void) { return 1; }
#endif
#ifdef MOCHIOS_TLS_RUNTIME
unsigned long __mochios_static_tls_v1(void) { return 1; }
__thread int root_tls_initial = 17;
__thread char root_tls_zero[73] __attribute__((aligned(64)));
#endif
#ifdef MOCHIOS_LIFECYCLE_RUNTIME
unsigned long __mochios_lifecycle_v1(void) { return 1; }
__attribute__((constructor)) static void scope_initialize(void) { ++root_override; }
__attribute__((destructor)) static void scope_finalize(void) { --root_override; }
#endif
#ifdef MOCHIOS_LIFECYCLE_BAD_CALLBACK
__attribute__((used, section(".init_array"))) static void (*const bad_callback)(void) = 0;
#endif
