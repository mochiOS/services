#ifdef ROOT
extern int library_value;
extern int library_function(int);
int root_value = 41;
static unsigned char sparse_zero[128 * 1024];
static int calls;
int (*function_pointer)(int) = library_function;
int _start(void) {
    if (!calls) {
        for (unsigned i = 0; i < sizeof(sparse_zero); ++i)
            if (sparse_zero[i]) return -1;
        sparse_zero[sizeof(sparse_zero) - 1] = 99;
    } else if (sparse_zero[sizeof(sparse_zero) - 1] != 99) return -2;
    return function_pointer(library_value) + calls++;
}
#else
int library_value = 31;
extern int root_value;
int library_function(int number) { return number + library_value + root_value + 17; }
#endif
