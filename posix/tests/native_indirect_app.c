#define _GNU_SOURCE 1
#define _POSIX_THREADS 1
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
int native_root_value = 21;
int native_root_fini;
static int root_constructor_value;
extern int native_pick(void);
extern int native_pointer_call(void);
extern int native_local_call(void);
extern int native_resolver_count(void);
extern int native_constructor_value(void);
extern int native_late_resolution(void);
extern void native_set_seed(int);
static void initialize(void) __attribute__((constructor));
static void initialize(void) { root_constructor_value = native_pick(); }
static void finalize(void) __attribute__((destructor));
static void finalize(void) { native_root_fini = 1; }
static void check(int condition, const char *expression) {
    if (!condition) { fprintf(stderr, "indirect-native: failed %s\n", expression); exit(1); }
}
#define CHECK(expression) check(!!(expression), #expression)
static void *thread_entry(void *unused) {
    (void)unused;
    CHECK(native_pick() == 73);
    native_set_seed(5);
    CHECK(native_pick() == 61 && native_pointer_call() == 61 && native_local_call() == 61);
    return (void *)(uintptr_t)1;
}
int main(int argc, char **argv) {
    const int after_exec = argc == 3 && strcmp(argv[1], "--after-exec") == 0;
    CHECK(argc == 2 || after_exec);
    const char *expected = argv[after_exec ? 2 : 1];
    CHECK(geteuid() == (strcmp(expected, "--expect-euid=501") == 0 ? 501 : 0));
    CHECK(root_constructor_value == 73 && native_constructor_value() == 146);
    CHECK(native_pick() == 73 && native_pointer_call() == 73 && native_local_call() == 73);
    CHECK(native_resolver_count() > 0 && !native_late_resolution());
    if (after_exec) { puts("indirect-native: reexec PASS"); return 42; }
    const int count = native_resolver_count();
    pthread_t thread;
    void *result = NULL;
    CHECK(pthread_create(&thread, NULL, thread_entry, NULL) == 0);
    CHECK(pthread_join(thread, &result) == 0 && result == (void *)(uintptr_t)1);
    CHECK(native_pick() == 73 && native_resolver_count() == count);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        if (native_pick() != 73 || native_local_call() != 73 || native_resolver_count() != count) _exit(2);
        char *arguments[] = {"indirect", "--after-exec", (char *)expected, NULL};
        execv("/system/bin/llvm-runtime-probe", arguments);
        _exit(3);
    }
    int status = -1;
    CHECK(waitpid(child, &status, 0) == child && status == (42 << 8));
    CHECK(native_resolver_count() == count && !native_late_resolution());
    printf("indirect-native: TLS/constructors/eager/pthread/fork/exec PASS euid=%lu\n", (unsigned long)geteuid());
    return 0;
}
