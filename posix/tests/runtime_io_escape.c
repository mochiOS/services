/* Host-only trampoline: a real C nonlocal exit must skip Rust I/O frames. */
#include <setjmp.h>
static jmp_buf destination;
int mochios_test_io_escape(void (*operation)(unsigned), unsigned mode) {
  int value = setjmp(destination);
  if (value)
    return value;
  operation(mode);
  return 0;
}
_Noreturn void mochios_test_io_jump(void) { longjmp(destination, 73); }
