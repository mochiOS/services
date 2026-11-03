#ifdef ROOT
extern volatile int library_value;
extern int library_function(int);
int root_value = 41;
int root_initialized;
__attribute__((constructor)) static void initialize(void) {
    root_initialized = library_value == 32 ? 1 : -1000;
    ++root_value;
}
__attribute__((destructor)) static void finalize(void) {
    root_initialized = 0;
    --root_value;
}
int evaluate(int number) {
    return library_function(number) + root_value + root_initialized;
}
#else
/* Keep the constructor observable; LLVM may fold nonvolatile increments into
   the initial data image and legitimately omit that constructor. */
volatile int library_value = 31;
__attribute__((constructor)) static void initialize(void) { ++library_value; }
__attribute__((destructor)) static void finalize(void) { --library_value; }
int library_function(int number) { return number + library_value; }
#ifdef DYNAMIC_TLS
__thread int late_thread_value = 19;
#endif
#endif
