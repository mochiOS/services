/* Host regression against the real newlib exit registry, with host allocation
 * and private symbol names. This does not replace the target implementation. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int newlib_register_exitproc(int, void (*)(void), void *, void *);
extern void newlib_call_exitprocs(int, void *);

static int fail_allocation;
static unsigned allocations, releases, calls;
static uintptr_t seen[256];

void *registry_malloc(size_t size) {
    if (fail_allocation)
        return NULL;
    void *result = malloc(size);
    if (result)
        ++allocations;
    return result;
}

void registry_free(void *pointer) {
    if (pointer)
        ++releases;
    free(pointer);
}

static void record(void *value) {
    assert(calls < sizeof seen / sizeof *seen);
    seen[calls++] = (uintptr_t)value;
}

static int add(uintptr_t value, void *dso) {
    return newlib_register_exitproc(2, (void (*)(void))record,
                                   (void *)value, dso);
}

static void plain(void) { record((void *)999); }

static void add_during_exit(void *value) {
    record(value);
    assert(add(1000, NULL) == 0);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    if (!strcmp(argv[1], "many")) {
        for (uintptr_t i = 1; i <= 128; ++i)
            assert(add(i, NULL) == 0);
        newlib_call_exitprocs(0, NULL);
        assert(calls == 128);
        for (unsigned i = 0; i < calls; ++i)
            assert(seen[i] == 128 - i);
    } else if (!strcmp(argv[1], "dso")) {
        int first, second;
        for (uintptr_t i = 1; i <= 128; ++i)
            assert(add(i, i % 2 ? &first : &second) == 0);
        newlib_call_exitprocs(0, &first);
        assert(calls == 64);
        for (unsigned i = 0; i < 64; ++i)
            assert(seen[i] == 127 - 2 * i);
        newlib_call_exitprocs(0, &first);
        assert(calls == 64);
        newlib_call_exitprocs(0, NULL);
        assert(calls == 128);
        for (unsigned i = 0; i < 64; ++i)
            assert(seen[64 + i] == 128 - 2 * i);
    } else if (!strcmp(argv[1], "allocation")) {
        for (uintptr_t i = 1; i <= 32; ++i)
            assert(add(i, NULL) == 0);
        fail_allocation = 1;
        assert(add(33, NULL) == -1);
        fail_allocation = 0;
        assert(add(33, NULL) == 0);
        newlib_call_exitprocs(0, NULL);
        assert(calls == 33);
        for (unsigned i = 0; i < calls; ++i)
            assert(seen[i] == 33 - i);
    } else if (!strcmp(argv[1], "registration")) {
        for (uintptr_t i = 1; i <= 65; ++i)
            assert(add(i, NULL) == 0);
        assert(newlib_register_exitproc(0, plain, NULL, NULL) == 0);
        assert(newlib_register_exitproc(2, (void (*)(void))add_during_exit,
                                       (void *)1001, NULL) == 0);
        newlib_call_exitprocs(0, NULL);
        assert(calls == 68 && seen[0] == 1001 && seen[1] == 1000 &&
               seen[2] == 999);
        for (unsigned i = 3; i < calls; ++i)
            assert(seen[i] == 68 - i);
    } else {
        return 2;
    }
    unsigned previous = calls;
    newlib_call_exitprocs(0, NULL);
    assert(calls == previous && allocations == releases);
    printf("newlib-exit: PASS %s\n", argv[1]);
    return 0;
}
