/* Exercise the first libc integration independently. The full three-operation
 * regression remains unchanged by default in native_file_admission.c. */
#define FILE_ADMISSION_FTRUNCATE_ONLY
#include "native_file_admission.c"
