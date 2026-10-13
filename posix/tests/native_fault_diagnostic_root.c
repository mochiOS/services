#define main readonly_cow_probe
#include "native_cow_readonly.c"
#undef main

int main(void) {
    if (readonly_cow_probe()) return 1;
    for (unsigned kind = 0; kind < 2; ++kind) {
        pid_t child = fork();
        if (child < 0) return 2;
        if (!child) {
            if (kind) __asm__ volatile("ud2");
            else __asm__ volatile("cli");
            _exit(0);
        }
        int status = 0;
        if (waitpid(child, &status, 0) != child || status == 0) return 3;
    }
    fprintf(stderr, "fault-diagnostic-root: PASS protected COW faults and user GP/UD termination without kernel memory dump\n");
    return 0;
}
