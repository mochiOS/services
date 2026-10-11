#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Isolated Input replacement, retaining its original capability manifest.
 * Exercises real IPC rejection, not successful session logout or teardown. */
enum { HANDLE_CLOSE = 626, INHERITED_HANDLE = 628, IPC_CREATE = 629, IPC_CALL = 632 };
struct attachment { uint32_t handle, reserved; uint64_t rights; };
struct attachments { uint32_t count, reserved; struct attachment handles[4]; };
_Static_assert(sizeof(struct attachments) == 72, "IPC object attachment ABI");
static int64_t native(uint64_t number, uint64_t a, uint64_t b, uint64_t c,
                      uint64_t d, uint64_t e, uint64_t f) {
    register uint64_t r10 __asm__("r10") = d;
    register uint64_t r8 __asm__("r8") = e;
    register uint64_t r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return (int64_t)number;
}
static int invalid_request(uint16_t opcode, uint32_t endpoint, uint32_t object, uint32_t flags,
                           uint32_t payload_len, uint64_t id) {
    unsigned char request[33] = {0}, response[64] = {0};
    memcpy(request, "POSX", 4);
    request[4] = 1;
    memcpy(request + 6, &opcode, sizeof(opcode));
    memcpy(request + 8, &id, sizeof(id));
    memcpy(request + 16, &flags, sizeof(flags));
    memcpy(request + 20, &payload_len, sizeof(payload_len));
    struct attachments handles = {0};
    if (object) {
        handles.count = 1;
        handles.handles[0].handle = object;
        handles.handles[0].rights = 1ULL << 2; /* SEND, not WAIT|SIGNAL */
    }
    int64_t result = native(IPC_CALL, endpoint, (uintptr_t)request, 32 + payload_len,
                            (uintptr_t)response, sizeof(response), (uintptr_t)&handles);
    int32_t status;
    uint64_t response_id;
    memcpy(&status, response + 24, sizeof(status));
    memcpy(&response_id, response + 8, sizeof(response_id));
    return result >= 0 && (uint32_t)result == 32 && handles.count == 0 &&
           !memcmp(response, "POSX", 4) && response[6] == 0 && response[7] == 0x80 &&
           response_id == id && status == -22;
}
int main(void) {
    fprintf(stderr, "native-tree-dispatch: start\n");
    uint64_t key;
    memcpy(&key, "POSXCTRL", sizeof(key));
    int64_t endpoint = native(INHERITED_HANDLE, key, 0, 0, 0, 0, 0);
    int64_t object = native(IPC_CREATE, 0, 0, 0, 0, 0, 0);
    if (endpoint <= 0 || object <= 0) return 1;
    for (uint16_t opcode = 61; opcode <= 62; ++opcode) {
        uint64_t id = (uint64_t)(opcode - 61) * 4;
        if (!invalid_request(opcode, (uint32_t)endpoint, 0, 0, 0, id + 1)) return 2;
        if (!invalid_request(opcode, (uint32_t)endpoint, (uint32_t)object, 0, 0, id + 2)) return 3;
        if (!invalid_request(opcode, (uint32_t)endpoint, (uint32_t)object, 1, 0, id + 3)) return 4;
        if (!invalid_request(opcode, (uint32_t)endpoint, (uint32_t)object, 0, 1, id + 4)) return 5;
    }
    if (native(HANDLE_CLOSE, (uint32_t)object, 0, 0, 0, 0, 0) || getpid() <= 0) return 6;
    fprintf(stderr, "native-tree-dispatch: PASS terminate and reclaim: missing object, wrong rights, flags, payload\n");
    return 0;
}
