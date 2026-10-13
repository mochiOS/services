/* Integration fixture only. Reject input subscription explicitly, then require
 * a reply from the real compositor after its mandatory first present. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum { IPC_SEND = 514, MEMORY_MAP = 582, MEMORY_UNMAP = 583,
       IPC_CREATE = 587, IPC_CALL = 588, IPC_REPLY = 589, IPC_WAIT = 590,
       HANDLE_CLOSE = 626, IPC_SEND_HANDLES = 630, DEBUG_WRITE = 660,
       MEMORY_CREATE = 671 };
struct attached { uint32_t handle, reserved; uint64_t rights; };
struct attachments { uint32_t count, flags; struct attached handles[4]; };

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
    uint32_t create[6] = {1, 1, 16, 16, (uint32_t)endpoint, (uint32_t)(endpoint >> 32)};
    message = native(IPC_CALL, compositor, (uintptr_t)create, sizeof(create), (uintptr_t)reply, sizeof(reply));
    if (failed(message) || (uint32_t)message != sizeof(reply) || reply[0]) return 8;
    uint64_t surface = 0;
    memcpy(&surface, &reply[1], 8);
    if (!surface) return 9;
    for (unsigned iteration = 0; iteration < 2; ++iteration) {
        unsigned char attach[28] = {2};
        memcpy(attach + 4, &surface, 8);
        const uint32_t layout[4] = {16, 16, 16, 1};
        memcpy(attach + 12, layout, sizeof(layout));
        message = native(IPC_CALL, compositor, (uintptr_t)attach, sizeof(attach), (uintptr_t)reply, sizeof(reply));
        if (failed(message) || reply[0]) return 10;
        uint64_t object = native(MEMORY_CREATE, 4096, 0, 0, 0, 0);
        if (failed(object) || !object) return 11;
        /* Sixth argument (offset) must be zero for MemoryMap. */
        register uint64_t offset __asm__("r9") = 0;
        register uint64_t access __asm__("r10") = 2;
        register uint64_t handle __asm__("r8") = object;
        uint64_t address = MEMORY_MAP;
        __asm__ volatile("syscall" : "+a"(address)
                         : "D"(UINT64_C(0)), "S"(UINT64_C(4096)), "d"(UINT64_C(3)),
                           "r"(access), "r"(handle), "r"(offset)
                         : "rcx", "r11", "memory");
        if (failed(address) || !address) return 12;
        memset((void *)(uintptr_t)address, iteration ? 0x80 : 0, 4096);
        unsigned char offer[32] = {'M','R','A','M',1,0,32,0};
        const uint64_t length = 4096;
        memcpy(offer + 24, &length, 8);
        struct attachments handles = {.count = 1, .handles = {{(uint32_t)object, 0, 65}}};
        if (failed(native(IPC_SEND_HANDLES, compositor, (uintptr_t)offer, sizeof(offer), (uintptr_t)&handles, 0))) return 13;
        if (failed(native(HANDLE_CLOSE, object, 0, 0, 0, 0))) return 14;
        unsigned char commit[12] = {4};
        memcpy(commit + 4, &surface, 8);
        message = native(IPC_CALL, compositor, (uintptr_t)commit, sizeof(commit), (uintptr_t)reply, sizeof(reply));
        if (failed(message) || reply[0]) return 15;
        if (failed(native(MEMORY_UNMAP, address, 4096, 0, 0, 0))) return 16;
    }
    unsigned char destroy[12] = {6};
    memcpy(destroy + 4, &surface, 8);
    message = native(IPC_CALL, compositor, (uintptr_t)destroy, sizeof(destroy), (uintptr_t)reply, sizeof(reply));
    if (failed(message) || reply[0]) return 17;
    return 0;
}

int main(int argc, char **argv) {
    int result = probe(argc, argv);
    char text[128];
    snprintf(text, sizeof(text), "compositor-buffer: %s first-present, 2 readonly surfaces, sender close, destroy result=%d\n",
             result ? "FAIL" : "PASS", result);
    native(DEBUG_WRITE, (uintptr_t)text, strlen(text), 0, 0, 0);
    if (result) return result;
    for (;;) {
        const struct timespec delay = {1, 0};
        if (nanosleep(&delay, 0)) return 7;
    }
}
