/* Real GD, LD and IE code generation for captured ELF link scopes. */
#if defined(TLS_GENERAL)
__thread int tls_library = 23;
__thread int tls_interpose = 29;
static __thread int tls_local __attribute__((tls_model("local-dynamic"))) = 41;
__thread char tls_zero[8195] __attribute__((aligned(8192)));
int *tls_general_address(void) { return &tls_library; }
int *tls_interpose_address(void) { return &tls_interpose; }
int *tls_local_address(void) { return &tls_local; }
char *tls_zero_address(void) { return tls_zero; }
#elif defined(TLS_INITIAL)
extern __thread int tls_library;
extern __thread int tls_root;
int *tls_initial_address(void) { return &tls_library; }
int *tls_root_address(void) { return &tls_root; }
#elif defined(TLS_ROOT)
__thread int tls_root = 11;
__thread int tls_interpose = 17;
extern int *tls_general_address(void);
extern int *tls_initial_address(void);
void *__tls_get_addr(void *index) { return index; }
void _start(void) {
  tls_root = *tls_general_address() + *tls_initial_address();
}
#endif
