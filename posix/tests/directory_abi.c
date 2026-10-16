#define _GNU_SOURCE
#include <dirent.h>
#include <stddef.h>

_Static_assert(sizeof(struct dirent) == 272, "directory record size");
_Static_assert(offsetof(struct dirent, d_type) == 8, "directory type offset");
_Static_assert(offsetof(struct dirent, d_name) == 9, "directory name offset");
_Static_assert(DT_REG == 8 && DT_DIR == 4 && DT_LNK == 10, "directory type values");
