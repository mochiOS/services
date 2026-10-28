#include "copy_fixture.h"
int check_copy(void) {
  if (legacy_data != 7 || current_data != 29 || provider_sum() != 36)
    return 1;
  void *addresses[] = {&legacy_data, &current_data, &copy_box, &copy_self,
                       copy_zero, copy_partial};
  for (int index = 0; index < 6; ++index)
    if (provider_address(index) != addresses[index])
      return 2;
  if (copy_box.value != &legacy_data || copy_box.marker != 17 ||
      copy_box.text[0] != 'c' || copy_box.text[8] != 'w' ||
      copy_self.self != &copy_self || copy_self.marker != 23)
    return 3;
  for (unsigned int index = 0; index < sizeof(copy_zero); ++index)
    if (copy_zero[index] != 0)
      return 4;
  for (unsigned int index = 0; index < sizeof(copy_partial); ++index)
    if (copy_partial[index] != 'a' + index)
      return 5;
  legacy_data = 11;
  current_data = 31;
  ++*copy_box.value;
  ++copy_self.marker;
  if (provider_sum() != 43 || provider_marker() != 24)
    return 6;
  legacy_data = 7;
  current_data = 29;
  copy_self.marker = 23;
  return 42;
}
#ifdef COPY_ORACLE
int main(void) { return check_copy() == 42 ? 0 : 1; }
#elif !defined(COPY_NATIVE)
int _start(void) { return check_copy(); }
#endif
