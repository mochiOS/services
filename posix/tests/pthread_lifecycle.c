#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

static int *child_errno_address;
static pthread_key_t test_key;
static int parent_specific_value;
static int child_specific_value;
static int destructor_calls;

static void destroy_specific_value(void *value) {
    if (value != &child_specific_value) {
        return;
    }
    ++destructor_calls;
    if (destructor_calls == 1) {
        pthread_setspecific(test_key, &child_specific_value);
    }
}

static void *return_argument(void *argument) {
    errno = EDOM;
    child_errno_address = &errno;
    if (errno != EDOM) {
        return 0;
    }
    if (pthread_getspecific(test_key) != 0) {
        return 0;
    }
    if (pthread_setspecific(test_key, &child_specific_value) != 0) {
        return 0;
    }
    if (pthread_getspecific(test_key) != &child_specific_value) {
        return 0;
    }
    return argument;
}

int main(void) {
    pthread_t thread;
    void *expected = (void *)(uintptr_t)0x5a5a;
    void *result = 0;

    if (pthread_key_create(&test_key, destroy_specific_value) != 0) {
        return 1;
    }
    if (pthread_setspecific(test_key, &parent_specific_value) != 0) {
        return 2;
    }
    errno = E2BIG;
    if (pthread_create(&thread, 0, return_argument, expected) != 0) {
        return 3;
    }
    if (pthread_equal(thread, pthread_self())) {
        return 4;
    }
    if (pthread_join(thread, &result) != 0) {
        return 5;
    }
    if (result != expected) {
        return 6;
    }
    if (child_errno_address == &errno) {
        return 7;
    }
    if (errno != E2BIG) {
        return 8;
    }
    if (pthread_getspecific(test_key) != &parent_specific_value) {
        return 9;
    }
    if (destructor_calls != 2) {
        return 10;
    }
    if (pthread_key_delete(test_key) != 0) {
        return 11;
    }
    if (pthread_getspecific(test_key) != 0) {
        return 12;
    }
    puts("pthread-lifecycle: pass");
    return 0;
}
