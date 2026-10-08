#include <pthread.h>
#include <stdint.h>

static void *return_argument(void *argument) {
    return argument;
}

int main(void) {
    pthread_t thread;
    void *expected = (void *)(uintptr_t)0x5a5a;
    void *result = 0;

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
    return 0;
}
