#define _GNU_SOURCE 1
#define _POSIX_THREADS 1
#include <elf.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
extern unsigned long getauxval(unsigned long);
extern void interpreter_root_entry(void);
volatile int interpreted_started;
static int constructor_observed;
static __thread int thread_value = 23;
static void before_main(void) __attribute__((constructor));
static void before_main(void) { constructor_observed = interpreted_started; }
static void check(int condition, const char *text) {
    if (!condition) { fprintf(stderr, "interpreter-native: failed %s\n", text); exit(1); }
}
#define CHECK(expression) check(!!(expression), #expression)
static void *thread_entry(void *argument) {
    (void)argument;
    CHECK(thread_value == 23);
    thread_value = 99;
    return (void *)(uintptr_t)1;
}
int main(int argc, char **argv) {
    int child = argc == 4 && !strcmp(argv[1], "--after-exec");
    CHECK(argc == 2 || child);
    const char *expected = argv[child ? 2 : 1];
    CHECK(geteuid() == (!strcmp(expected, "--expect-euid=501") ? 501 : 0));
    CHECK(interpreted_started == 1 && constructor_observed == 1);
    CHECK(getauxval(7) >= 0x40000000UL);
    CHECK(getauxval(9) == (uintptr_t)interpreter_root_entry);
    CHECK(getauxval(0x6d000004) == 0);
    CHECK(getauxval(4) == sizeof(Elf64_Phdr));
    const Elf64_Phdr *headers = (const void *)(uintptr_t)getauxval(3);
    size_t count = getauxval(5);
    CHECK(count > 0 && count < 32);
    int source = open("/system/bin/llvm-runtime-probe", O_RDONLY);
    CHECK(source >= 0);
    Elf64_Ehdr elf;
    CHECK(pread(source, &elf, sizeof(elf), 0) == sizeof(elf));
    CHECK(elf.e_phnum == count);
    Elf64_Phdr original[32];
    CHECK(pread(source, original, count * sizeof(*original), elf.e_phoff) == (ssize_t)(count * sizeof(*original)));
    CHECK(close(source) == 0 && !memcmp(headers, original, count * sizeof(*original)));
    int interpreter = 0;
    for (size_t i = 0; i < count; ++i) {
        if (headers[i].p_type == PT_INTERP) {
            CHECK(!strcmp((const void *)(uintptr_t)headers[i].p_vaddr, "/system/libraries/interpreter-probe/ld.native.so"));
            ++interpreter;
        }
    }
    CHECK(interpreter == 1 && thread_value == 23);
    if (child) {
        char byte = 0;
        int fd = atoi(argv[3]);
        CHECK(read(fd, &byte, 1) == 1 && byte == 'x' && close(fd) == 0);
        puts("interpreter-native: reexec and inherited FD PASS");
        return 42;
    }
    pthread_t thread;
    void *result = NULL;
    CHECK(pthread_create(&thread, NULL, thread_entry, NULL) == 0);
    CHECK(pthread_join(thread, &result) == 0 && result == (void *)(uintptr_t)1 && thread_value == 23);
    int fds[2];
    CHECK(pipe(fds) == 0 && write(fds[1], "x", 1) == 1);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        char descriptor[24];
        snprintf(descriptor, sizeof(descriptor), "%d", fds[0]);
        CHECK(close(fds[1]) == 0);
        char *arguments[] = {"interpreter-probe", "--after-exec", (char *)expected, descriptor, NULL};
        execv("/system/bin/llvm-runtime-probe", arguments);
        _exit(3);
    }
    CHECK(close(fds[0]) == 0 && close(fds[1]) == 0);
    int status = -1;
    CHECK(waitpid(pid, &status, 0) == pid && status == (42 << 8));
    printf("interpreter-native: entry/AT_BASE/AT_ENTRY/original-PHDR/constructor/TLS/pthread/fork/exec/FD PASS euid=%lu\n", (unsigned long)geteuid());
    return 0;
}
