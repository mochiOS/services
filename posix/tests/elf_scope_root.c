extern int shared_value;
extern int shared_function(int);
extern int optional_value __attribute__((weak));
int root_override = 41;
int *root_shared_pointer = &shared_value;
int *root_weak_pointer = &optional_value;
int (*root_function_pointer)(int) = shared_function;
void _start(void) { root_override = shared_function(shared_value); }
