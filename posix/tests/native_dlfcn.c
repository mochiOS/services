/* Public libc ABI, not a direct invocation of the Rust loader internals. */
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *library = "/system/tests/dlfcn387/root.so";
static void *expected;
static pthread_barrier_t barrier;
static int finalized;
static void normal_exit(int value) {
    assert(value == 21);
    puts("public-dlfcn: normal exit finalizers PASS");
}

static void *worker(void *argument) {
    (void)argument;
    int result = pthread_barrier_wait(&barrier);
    assert(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
    assert(dlerror() == NULL);
    for (int i = 0; i < 2; ++i) {
        void *handle = dlopen(library, RTLD_NOW | RTLD_LOCAL);
        assert(handle == expected);
        int (*evaluate)(int) = (int (*)(int))dlsym(handle, "evaluate");
        assert(evaluate && evaluate(7) == 82);
        assert(dlsym(handle, "absent_worker_symbol") == NULL);
        assert(dlerror() != NULL);
        assert(dlerror() == NULL);
        assert(dlclose(handle) == 0);
    }
    return NULL;
}

int main(void) {
    alarm(120);
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("public-dlfcn: begin");
    assert(dlerror() == NULL);
    assert(setenv("LD_LIBRARY_PATH", "/system/tests/dlfcn387", 1) == 0);
    expected = dlopen(library, RTLD_NOW | RTLD_LOCAL);
    if (!expected) {
        printf("public-dlfcn: first open failed: errno=%d %s\n", errno, dlerror());
        return 1;
    }
    void *again = dlopen("root.so", RTLD_LAZY | RTLD_LOCAL);
    assert(again == expected);
    int (*evaluate)(int) = (int (*)(int))dlsym(expected, "evaluate");
    int (*count)(void) = (int (*)(void))dlsym(expected, "initialization_count");
    void (*sink)(int *) = (void (*)(int *))dlsym(expected, "finalizer_sink");
    assert(evaluate && count && sink);
    assert(evaluate(7) == 82 && count() == 1);
    assert(dlopen("/system/tests/dlfcn387/libdlfcn387.so", RTLD_NOW) == NULL);
    assert(errno == EBUSY && dlerror() != NULL);
    assert(evaluate(7) == 82 && count() == 1);
    sink(&finalized);
    assert(dlsym(expected, "absent_parent_symbol") == NULL);
    pthread_t threads[4];
    assert(pthread_barrier_init(&barrier, NULL, 4) == 0);
    for (int i = 0; i < 4; ++i) assert(pthread_create(&threads[i], NULL, worker, NULL) == 0);
    for (int i = 0; i < 4; ++i) assert(pthread_join(threads[i], NULL) == 0);
    assert(pthread_barrier_destroy(&barrier) == 0);
    assert(dlerror() != NULL); /* worker errors did not consume this thread's error */
    assert(dlerror() == NULL);
    puts("public-dlfcn: concurrent refs and thread errors pass");
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(evaluate(7) == 82);
        assert(dlclose(expected) == 0 && finalized == 0);
        assert(dlclose(again) == 0 && finalized == 21);
        _exit(0);
    }
    int status = -1;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(finalized == 0 && evaluate(7) == 82);
    assert(dlclose(expected) == 0 && finalized == 0 && evaluate(7) == 82);
    assert(dlclose(again) == 0 && finalized == 21);
    assert(dlsym(expected, "evaluate") == NULL && dlerror() != NULL);
    assert(dlclose(expected) == -1 && dlerror() != NULL);
    assert(dlopen("/system/tests/dlfcn387/unsigned.so", RTLD_NOW) == NULL && dlerror() != NULL);
    assert(dlopen("/system/tests/dlfcn387/tampered.so", RTLD_NOW) == NULL && dlerror() != NULL);
    assert(dlopen("/system/tests/dlfcn387/risky.so", RTLD_NOW) == NULL && dlerror() != NULL);
    assert(dlopen((const char *)1, RTLD_NOW) == NULL && dlerror() != NULL);
    assert(dlopen(library, RTLD_NOW | RTLD_GLOBAL) == NULL && dlerror() != NULL);
    assert(dlopen(NULL, RTLD_NOW) == NULL && dlerror() != NULL);
    void *fresh = dlopen(library, RTLD_NOW);
    assert(fresh && fresh != expected);
    count = (int (*)(void))dlsym(fresh, "initialization_count");
    assert(count && count() == 1);
    finalized = 0;
    sink = (void (*)(int *))dlsym(fresh, "finalizer_sink");
    void (*hook)(void (*)(int)) = (void (*)(void (*)(int)))dlsym(fresh, "finalizer_hook");
    assert(sink && hook);
    sink(&finalized);
    hook(normal_exit);
    assert(dlerror() == NULL);
    puts("public-dlfcn: signed dependency calls, ctor/fini, refs, fork, errors PASS");
    return 0;
}
