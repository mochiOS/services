/* Integration fixture only. Reject input subscription explicitly, then require
 * a reply from the real compositor after its mandatory first present. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum { IPC_SEND = 514, IPC_CREATE = 587, IPC_CALL = 588,
       IPC_REPLY = 589, IPC_WAIT = 590, DEBUG_WRITE = 660 };

static uint64_t native(uint64_t number, uint64_t a, uint64_t b, uint64_t c,
                       uint64_t d, uint64_t e) {
    register uint64_t r10 __asm__("r10") = d;
    register uint64_t r8 __asm__("r8") = e;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8)
                     : "rcx", "r11", "memory");
    return number;
}

static int failed(uint64_t value) {
    return (int64_t)value >= -4095 && (int64_t)value < 0;
}

static int probe(int argc, char **argv) {
    uint64_t manager = 0, token = 0;
    const char prefix[] = "--service-ready=";
    for (int i = 1; i < argc; ++i) {
        if (strncmp(argv[i], prefix, sizeof(prefix) - 1)) continue;
        char *separator, *end;
        manager = strtoull(argv[i] + sizeof(prefix) - 1, &separator, 10);
        if (*separator != ':') return 1;
        token = strtoull(separator + 1, &end, 10);
        if (*end) return 1;
    }
    if (!manager || !token) return 1;
    uint64_t endpoint = native(IPC_CREATE, 0, 0, 0, 0, 0);
    if (!endpoint || failed(endpoint)) return 2;
    unsigned char ready[20] = {'S','D','R','Y',1,0,1,0};
    memcpy(ready + 8, &token, 8);
    if (failed(native(IPC_SEND, manager, (uintptr_t)ready, sizeof(ready), 0, 0))) return 3;
    unsigned char request[32] = {0};
    uint64_t message = native(IPC_WAIT, (uintptr_t)request, sizeof(request), endpoint, 0, 0);
    uint32_t opcode = 0;
    memcpy(&opcode, request, 4);
    if (failed(message) || (uint32_t)message != 16 || opcode != 0x53554253) return 4;
    uint64_t compositor = message >> 32;
    const unsigned char unavailable = 38; /* ENOSYS: no input implementation. */
    if (failed(native(IPC_REPLY, compositor, (uintptr_t)&unavailable, 1, 0, 0))) return 5;
    /* The production server only starts receiving after first-present succeeds. */
    uint32_t query = 9, reply[4] = {0};
    message = native(IPC_CALL, compositor, (uintptr_t)&query, sizeof(query), (uintptr_t)reply, sizeof(reply));
    if (failed(message) || (uint32_t)message != sizeof(reply) || reply[0]) return 6;
    return 0;
}

int main(int argc, char **argv) {
    int result = probe(argc, argv);
    char text[128];
    snprintf(text, sizeof(text), "compositor-buffer: %s real compositor first-present and RPC result=%d\n",
             result ? "FAIL" : "PASS", result);
    native(DEBUG_WRITE, (uintptr_t)text, strlen(text), 0, 0, 0);
    if (result) return result;
    for (;;) {
        const struct timespec delay = {1, 0};
        if (nanosleep(&delay, 0)) return 7;
    }
}
