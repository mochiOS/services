/* A real authenticated DSO; constructor inspection exercises loader reentry. */
#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <link.h>
#include <stdint.h>
#include <string.h>

int native_unix_value(int value) { return value + 123; }
static int constructor_result;
static int count_self(struct dl_phdr_info *info, size_t size, void *data)
{
    if (size < sizeof(*info)) return 91;
    if (strstr(info->dlpi_name, "libunix-inspection.so")) ++*(int *)data;
    return 0;
}
__attribute__((constructor)) static void initialize(void)
{
    Dl_info information;
    int count = 0;
    constructor_result = dladdr((void *)(uintptr_t)&native_unix_value, &information)
        && information.dli_sname && !strcmp(information.dli_sname, "native_unix_value")
        && dl_iterate_phdr(count_self, &count) == 0 && count == 1;
}
int native_unix_constructor_result(void) { return constructor_result; }
