int shared_value = 31;
int root_override = 7;
__attribute__((visibility("protected"))) int protected_value = 13;
__attribute__((visibility("hidden"))) int hidden_value = 17;
int *dependency_root_pointer = &root_override;
int *dependency_protected_pointer = &protected_value;
int shared_function(int number) { return number + shared_value + root_override + hidden_value; }
#ifdef MOCHIOS_LIFECYCLE_CALLBACKS
__attribute__((constructor)) static void scope_initialize(void) { ++shared_value; }
__attribute__((destructor)) static void scope_finalize(void) { --shared_value; }
#endif
