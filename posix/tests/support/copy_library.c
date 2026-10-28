#include "copy_fixture.h"
int old_data = 7;
int new_data = 29;
__asm__(".symver old_data,api_data@API_1");
__asm__(".symver new_data,api_data@@API_2");
struct CopyBox copy_box = {&legacy_data, 17, "copy-view"};
struct CopySelf copy_self = {&copy_self, 23};
unsigned char copy_zero[8193];
unsigned char copy_partial[7] = {'a', 'b', 'c', 'd', 'e', 'f', 'g'};
void *provider_address(int which) {
  switch (which) {
  case 0: return &legacy_data;
  case 1: return &current_data;
  case 2: return &copy_box;
  case 3: return &copy_self;
  case 4: return copy_zero;
  default: return copy_partial;
  }
}
int provider_sum(void) { return legacy_data + current_data; }
long provider_marker(void) { return copy_self.marker; }
