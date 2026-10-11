#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

static int check_formats(void) {
    unsigned long long endpoint = 0, token = 0;
    long long signed_value = 0;
    size_t size = 0;
    intmax_t widest = 0;
    ptrdiff_t difference = 0;
    char output[160];
    int consumed = 0;

    if (sscanf("4294967297:18446744073709551615!", "%llu:%llu%n",
               &endpoint, &token, &consumed) != 2 ||
        endpoint != 4294967297ULL || token != ULLONG_MAX || consumed != 31)
        return 1;
    if (sscanf("-9223372036854775807 4294967297 -1234567890123 -456",
               "%lld %zu %jd %td", &signed_value, &size, &widest, &difference) != 4 ||
        signed_value != -9223372036854775807LL || size != (size_t)4294967297ULL ||
        widest != (intmax_t)-1234567890123LL || difference != -456)
        return 2;
    if (snprintf(output, sizeof output, "%llu:%llu", endpoint, token) != 31 ||
        strcmp(output, "4294967297:18446744073709551615") != 0)
        return 3;
    if (snprintf(output, sizeof output, "%zu/%jd/%td", size, widest, difference) != 30 ||
        strcmp(output, "4294967297/-1234567890123/-456") != 0)
        return 4;
    if (snprintf(output, sizeof output, "%2$d/%1$d", 12, 34) != 5 ||
        strcmp(output, "34/12") != 0)
        return 5;
    if (snprintf(output, sizeof output, "%2$llu/%1$llu", endpoint, token) != 31 ||
        strcmp(output, "18446744073709551615/4294967297") != 0)
        return 11;
    int first = 0, second = 0;
    if (sscanf("34/12", "%2$d/%1$d", &first, &second) != 2 || first != 12 || second != 34)
        return 6;
    long double real = 0;
    if (sscanf("1.25", "%Lf", &real) != 1 || real != 1.25L ||
        snprintf(output, sizeof output, "%.2Lf", real) != 4 || strcmp(output, "1.25") != 0)
        return 7;
    /* Invalid input must be a matching failure, not a successful conversion. */
    if (sscanf("no integer", "%llu", &token) != 0)
        return 8;
    wchar_t wide_output[80];
    int wide_count = swprintf(wide_output, 80, L"%2$llu/%1$llu", endpoint, token);
    if (wide_count != 31 || wcscmp(wide_output, L"18446744073709551615/4294967297") != 0) {
        fprintf(stderr, "stdio-formats: wide count=%d endpoint=%llu token=%llu output=",
                wide_count, endpoint, token);
        for (size_t index = 0; index < 79 && wide_output[index] != 0; ++index)
            fprintf(stderr, "%c", (int)wide_output[index]);
        fprintf(stderr, "\n");
        return 9;
    }
    endpoint = token = 0;
    if (swscanf(L"18446744073709551615/4294967297", L"%2$llu/%1$llu", &endpoint, &token) != 2 ||
        endpoint != 4294967297ULL || token != ULLONG_MAX)
        return 10;
    fprintf(stderr, "stdio-formats: pass 64-bit/C99/positional/long-double\n");
    return 0;
}

int main(void) {
    int result = check_formats();
    if (result != 0)
        fprintf(stderr, "stdio-formats: fail stage=%d\n", result);
    return result;
}
