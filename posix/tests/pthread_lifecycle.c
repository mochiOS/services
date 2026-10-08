#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

static int *child_errno_address;

static void *return_argument(void *argument) {
    errno = EDOM;
    child_errno_address = &errno;
    if (errno != EDOM) {
        return 0;
    }
    return argument;
}

int main(void) {
    pthread_t thread;
    void *expected = (void *)(uintptr_t)0x5a5a;
    void *result = 0;

    errno = E2BIG;
    if (pthread_create(&thread, 0, return_argument, expected) != 0) {
        return 1;
    }
    if (pthread_equal(thread, pthread_self())) {
        return 2;
    }
    if (pthread_join(thread, &result) != 0) {
        return 3;
    }
    if (result != expected) {
        return 4;
    }
    if (child_errno_address == &errno) {
        return 5;
    }
    if (errno != E2BIG) {
        return 6;
    }
    puts("pthread-lifecycle: pass");
    return 0;
}
