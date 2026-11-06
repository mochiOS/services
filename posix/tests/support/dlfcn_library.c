#ifdef ROOT
extern volatile int dependency_value;
extern int dependency_function(int);
extern void dependency_sink(int *);
extern void dependency_hook(void (*)(int));
static volatile int initialized;
static int *sink;
__attribute__((constructor)) static void initialize(void) {
    if (dependency_value == 32) ++initialized;
    else initialized = -1000;
}
__attribute__((destructor)) static void finalize(void) {
    if (sink) *sink = *sink * 10 + 2;
    initialized = 0;
}
int evaluate(int n) { return dependency_function(n) + 42 + initialized; }
int initialization_count(void) { return initialized; }
void finalizer_sink(int *value) { sink = value; dependency_sink(value); }
void finalizer_hook(void (*hook)(int)) { dependency_hook(hook); }
#else
volatile int dependency_value = 31;
static int *sink;
static void (*hook)(int);
__attribute__((constructor)) static void initialize(void) { ++dependency_value; }
__attribute__((destructor)) static void finalize(void) {
    if (sink) *sink = *sink * 10 + 1;
    if (hook && sink) hook(*sink);
    --dependency_value;
}
int dependency_function(int n) { return n + dependency_value; }
void dependency_sink(int *value) { sink = value; }
void dependency_hook(void (*value)(int)) { hook = value; }
#endif
