/* Test-only readiness gate for native launch integration. This is not an input
 * driver: it deliberately does not implement input or compositor protocols. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char **argv) {
    uint64_t endpoint = 0, token = 0;
    const char prefix[] = "--service-ready=";
    for (int i = 1; i < argc; ++i) {
        if (strncmp(argv[i], prefix, sizeof(prefix) - 1) != 0)
            continue;
        char *separator, *end;
        endpoint = strtoull(argv[i] + sizeof(prefix) - 1, &separator, 10);
        if (*separator != ':')
            return 1;
        token = strtoull(separator + 1, &end, 10);
        if (*end == 0)
            break;
        return 1;
    }
    if (!endpoint || !token)
        return 1;
    unsigned char message[20] = {0};
    uint32_t magic = 0x59524453;
    uint16_t version = 1, kind = 1;
    uint64_t cookie = token;
    memcpy(message, &magic, 4);
    memcpy(message + 4, &version, 2);
    memcpy(message + 6, &kind, 2);
    memcpy(message + 8, &cookie, 8);
    uint64_t number = 514; /* IpcSend: generic message delivery. */
    __asm__ volatile("syscall"
                     : "+a"(number)
                     : "D"((uint64_t)endpoint), "S"(message), "d"(sizeof(message))
                     : "rcx", "r11", "memory");
    if ((int64_t)number < 0)
        return 2;
    fprintf(stderr, "native-bootstrap-ready: test gate sent\n");
    for (;;) {
        const struct timespec delay = {1, 0};
        if (nanosleep(&delay, 0) != 0)
            return 3;
    }
}
