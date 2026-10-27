/* Host linker fixture: one dependency-free ET_DYN with real GOT/PLT bindings. */
extern int missing_data __attribute__((weak));
extern int missing_function(void) __attribute__((weak));
int symbol_value = 31;
int symbol_function(int number) { return number + symbol_value; }
int *symbol_pointer = &symbol_value;
int (*function_pointer)(int) = symbol_function;
int *weak_pointer = &missing_data;
__asm__(".globl literal_value\n.set literal_value, 0x1234");
extern int literal_value;
int *absolute_pointer = &literal_value;
void _start(void) {
  symbol_value = symbol_function(3);
  if (&missing_data) symbol_value += missing_data;
  if (missing_function) symbol_value += missing_function();
}
