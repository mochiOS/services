#include <dlfcn.h>
#include <stdio.h>

/* Separate process: comparison uses the host GNU loader, never our planner. */
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    void *image = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!image) { fprintf(stderr, "%s\n", dlerror()); return 3; }
    int (*entry)(void) = dlsym(image, "_start");
    unsigned long (*seen)(void) = dlsym(image, "get_seen");
    unsigned long (*calls)(void) = dlsym(image, "get_local_calls");
    unsigned long *zero = dlsym(image, "zero_slot");
    if (!entry || !seen || !calls || !zero) return 4;
    printf("%d %lu %lu %lu\n", entry(), seen(), calls(), *zero);
    return dlclose(image) ? 5 : 0;
}
