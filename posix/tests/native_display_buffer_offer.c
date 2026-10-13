#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

enum { FIND_PROCESS = 518, IPC_CALL = 588, IPC_SEND_HANDLES = 630,
       MEMORY_MAP = 582, MEMORY_UNMAP = 583, HANDLE_CLOSE = 626,
       MEMORY_CREATE = 671, DEBUG_WRITE = 660 };
struct attached { uint32_t handle, reserved; uint64_t rights; };
struct attachments { uint32_t count, delivery_flags; struct attached handles[4]; };

static uint64_t native(uint64_t number, uint64_t a, uint64_t b, uint64_t c,
                       uint64_t d, uint64_t e, uint64_t f) {
    register uint64_t r10 __asm__("r10") = d;
    register uint64_t r8 __asm__("r8") = e;
    register uint64_t r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return number;
}

static int failed(uint64_t result) {
    int64_t signed_result = (int64_t)result;
    return signed_result >= -4095 && signed_result < 0;
}

static int probe(void) {
    const char name[] = "display.driver";
    uint64_t endpoint = native(FIND_PROCESS, (uintptr_t)name, strlen(name), 0, 0, 0, 0);
    if (!endpoint || (int64_t)endpoint < 0) return 1;
    uint32_t request[5] = {1}, reply[5] = {0};
    uint64_t information = native(IPC_CALL, endpoint, (uintptr_t)request, 4, (uintptr_t)reply, sizeof(reply), 0);
    if (failed(information) || (uint32_t)information != sizeof(reply) || reply[0]) return 2;
    uint64_t bytes = (uint64_t)reply[3] * reply[2] * 4;
    if (!bytes || bytes > 16 * 1024 * 1024) return 3;
    request[0] = 3;
    if (failed(native(IPC_CALL, endpoint, (uintptr_t)request, 4, (uintptr_t)reply, sizeof(reply), 0)) || reply[0]) return 4;
    /* Query geometry again after the status-only ownership reply. */
    request[0] = 1;
    information = native(IPC_CALL, endpoint, (uintptr_t)request, 4, (uintptr_t)reply, sizeof(reply), 0);
    if (failed(information) || (uint32_t)information != sizeof(reply) || reply[0]) return 5;
    request[0] = 2;
    memcpy(&request[1], &reply[1], 16);
    uint64_t capacity = (bytes + 4095) & ~UINT64_C(4095);
    for (unsigned iteration = 0; iteration < 4; ++iteration) {
        uint64_t object = native(MEMORY_CREATE, capacity, 0, 0, 0, 0, 0);
        if ((int64_t)object < 0) return 6;
        uint64_t address = native(MEMORY_MAP, 0, capacity, 3, 2, object, 0);
        if ((int64_t)address < 0) return 7;
        memset((void *)(uintptr_t)address, 0, (size_t)capacity);
        unsigned char offer[32] = {'M','R','A','M',1,0,32,0};
        memcpy(offer + 24, &capacity, 8);
        struct attachments handles = {.count = 1, .handles = {{(uint32_t)object, 0, 65}}};
        if (native(IPC_SEND_HANDLES, endpoint, (uintptr_t)offer, sizeof(offer), (uintptr_t)&handles, 0, 0) != 0) return 8;
        if (native(HANDLE_CLOSE, object, 0, 0, 0, 0, 0) != 0) return 9;
        memset(reply, 0, sizeof(reply));
        uint64_t result = native(IPC_CALL, endpoint, (uintptr_t)request, sizeof(request), (uintptr_t)reply, sizeof(reply), 0);
        if (failed(result) || reply[0]) {
            char text[96];
            snprintf(text, sizeof(text), "display-offer: present result=%lld status=%u\n", (long long)result, reply[0]);
            native(DEBUG_WRITE, (uintptr_t)text, strlen(text), 0, 0, 0, 0);
            return 10;
        }
        if (native(MEMORY_UNMAP, address, capacity, 0, 0, 0, 0) != 0) return 11;
    }
    return 0;
}

int main(void) {
    int result = probe();
    char text[96];
    snprintf(text, sizeof(text), "display-offer: %s 4 readonly buffer replacements result=%d\n", result ? "FAIL" : "PASS", result);
    native(DEBUG_WRITE, (uintptr_t)text, strlen(text), 0, 0, 0, 0);
    return result;
}
