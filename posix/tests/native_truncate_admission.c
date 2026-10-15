/* Keep the unthrottled reader and all 64 updates; isolate the libc pathname
 * integration without depending on the not-yet-migrated O_TRUNC path. */
#define FILE_ADMISSION_PATH_TRUNCATE_ONLY
#include "native_file_admission.c"
