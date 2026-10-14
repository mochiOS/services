#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

enum { MEMORY_MAP = 582, MEMORY_UNMAP = 583, MEMORY_CREATE = 671,
       HANDLE_CLOSE = 626, MEMORY_RESIZE = 686 };
static volatile unsigned handled;
static volatile uintptr_t repair_address;
static volatile uint64_t repair_object;

static uint64_t native(uint64_t n, uint64_t a, uint64_t b, uint64_t c,
                       uint64_t d, uint64_t e, uint64_t f) {
    register uint64_t r10 __asm__("r10") = d;
    register uint64_t r8 __asm__("r8") = e;
    register uint64_t r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "+a"(n)
                     : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return n;
}

static void repair(int signal) {
    if (signal == SIGSEGV && repair_address) {
        if (mprotect((void *)repair_address, 4096, PROT_READ | PROT_WRITE)) _exit(90);
    } else if (signal == SIGBUS && repair_object) {
        if (native(MEMORY_RESIZE, repair_object, 8192, 0, 0, 0, 0)) _exit(91);
    } else {
        _exit(92);
    }
    ++handled;
    errno = 99;
}

static uint64_t outside_backing(int shared, uint64_t *object) {
    *object = native(MEMORY_CREATE, 4096, 1, 0, 0, 0, 0);
    if ((int64_t)*object <= 0) return 0;
    uint64_t memory = native(MEMORY_MAP, 0, 4096, 1, shared ? 2 : 0, *object, 4096);
    return (int64_t)memory > 0 ? memory : 0;
}

int main(void) {
    struct sigaction action = {0};
    action.sa_handler = repair;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGSEGV, &action, NULL) || sigaction(SIGBUS, &action, NULL)) return 1;
    for (unsigned attempt = 1; attempt <= 3; ++attempt) {
        void *memory = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (memory == MAP_FAILED || mprotect(memory, 4096, PROT_READ)) return 2;
        repair_address = (uintptr_t)memory;
        errno = 42;
        *(volatile unsigned char *)memory = 0xa7;
        if (handled != attempt || errno != 42 || *(volatile unsigned char *)memory != 0xa7) return 3;
        if (munmap(memory, 4096)) return 4;
        repair_address = 0;
    }
    for (int shared = 0; shared <= 1; ++shared) {
        uint64_t object;
        uint64_t memory = outside_backing(shared, &object);
        if (!memory) return 5;
        repair_object = object;
        errno = 43;
        unsigned char byte = *(volatile unsigned char *)(uintptr_t)memory;
        if (byte != 0 || handled != 4u + shared || errno != 43) return 6;
        repair_object = 0;
        if (native(MEMORY_UNMAP, memory, 4096, 0, 0, 0, 0) ||
            native(HANDLE_CLOSE, object, 0, 0, 0, 0, 0)) return 7;
    }
    for (int kind = 0; kind < 7; ++kind) {
        int signal = kind == 0 || kind == 3 || kind == 4 ? SIGSEGV : SIGBUS;
        pid_t child = fork();
        if (child < 0) return 8;
        if (!child) {
            action.sa_handler = kind < 3 ? SIG_DFL : (kind == 4 || kind == 6 ? SIG_IGN : repair);
            if (sigaction(signal, &action, NULL)) _exit(93);
            if (kind == 3 || kind == 5) {
                sigset_t set;
                sigemptyset(&set); sigaddset(&set, signal);
                if (sigprocmask(SIG_BLOCK, &set, NULL)) _exit(94);
            }
            uint64_t address = 0, object;
            if (signal == SIGBUS) {
                address = outside_backing(kind == 2, &object);
                if (!address) _exit(95);
            }
            __asm__ volatile("mov (%%rax), %%rax" : "+a"(address) : : "memory");
            _exit(96);
        }
        int status;
        if (waitpid(child, &status, 0) != child || !WIFSIGNALED(status) || WTERMSIG(status) != signal) {
            fprintf(stderr, "posix-memory-fault: wait FAIL kind=%d status=%x expected=%d\n", kind, status, signal);
            return 9;
        }
    }
    puts("posix-memory-fault: PASS handlers repair/retry, errno, private/shared backing, fatal defaults and waitpid signals");
    return 0;
}
