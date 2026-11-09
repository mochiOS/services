/* A real authenticated DSO; constructor inspection exercises loader reentry. */
#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <link.h>
#include <math.h>
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

/* Force public process math imports, including operations the compiler could
   otherwise lower to instructions or Rust's private compiler builtins. */
double native_unix_math_result(void)
{
    double (*volatile floor_function)(double) = floor;
    double (*volatile sqrt_function)(double) = sqrt;
    double (*volatile fmod_function)(double, double) = fmod;
    return floor_function(7.25) + sqrt_function(49.0) + fmod_function(7.0, 3.0);
}

/* No process-global state: these calls must use private compiler-rt helpers
   from the SDK, rather than importing hidden Rust compiler builtins. */
static __attribute__((noinline)) __int128 signed_divide(__int128 a, __int128 b) { return a / b; }
static __attribute__((noinline)) __int128 signed_remainder(__int128 a, __int128 b) { return a % b; }
static __attribute__((noinline)) unsigned __int128 unsigned_divide(unsigned __int128 a, unsigned __int128 b) { return a / b; }
static __attribute__((noinline)) unsigned __int128 unsigned_remainder(unsigned __int128 a, unsigned __int128 b) { return a % b; }
int native_unix_integer_result(void)
{
    volatile __int128 a = -(((__int128)1 << 100) + 7), b = 3;
    volatile unsigned __int128 u = ((unsigned __int128)1 << 100) + 7, v = 3;
    return signed_divide(a, b) == -(((__int128)1 << 100) / 3 + 2)
        && signed_remainder(a, b) == -2
        && unsigned_divide(u, v) == (((unsigned __int128)1 << 100) / 3 + 2)
        && unsigned_remainder(u, v) == 2;
}
