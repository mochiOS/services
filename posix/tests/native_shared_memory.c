#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Native ABI values are checked against mnu-abi by shared_memory_abi.rs. */
enum { MEMORY_MAP = 582, MEMORY_UNMAP = 583, MEMORY_PROTECT = 584,
       IPC_REPLY = 589, HANDLE_CLOSE = 626, HANDLE_DUPLICATE = 627,
       IPC_CREATE = 629, IPC_SEND_HANDLES = 630, IPC_RECV_HANDLES = 631,
       IPC_CALL_HANDLES = 632, MEMORY_OBJECT_CREATE = 671, MEMORY_OBJECT_LENGTH = 672 };
#define READ 1ULL
#define WRITE 2ULL
#define MAP 64ULL
#define DUPLICATE (1ULL << 62)
#define TRANSFER (1ULL << 63)
#define SHARED 2ULL
struct attached_handle { uint32_t handle, reserved; uint64_t rights; };
struct attachments { uint32_t count, delivery_flags; struct attached_handle handles[4]; };
_Static_assert(sizeof(struct attached_handle) == 16, "attachment ABI");
_Static_assert(sizeof(struct attachments) == 72, "attachments ABI");

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

static uint64_t map(uint64_t handle, uint64_t size, uint64_t access, uint64_t offset) {
    return native(MEMORY_MAP, 0, size, access, SHARED, handle, offset);
}

static int probe(void) {
    fprintf(stderr, "shared-memory: start\n");
    /* Retired native entry, not newlib errno: unknown syscall is -38. */
    if ((int64_t)native(585, 0, 0, 0, 0, 0, 0) != -38) return 52;
    fprintf(stderr, "shared-memory: legacy entry retired\n");
    if ((int64_t)native(MEMORY_OBJECT_CREATE, 0, 0, 0, 0, 0, 0) !=
        INT64_C(-262139))
      return 1;
    if ((int64_t)native(MEMORY_OBJECT_CREATE, 4096, 2, 0, 0, 0, 0) !=
        INT64_C(-262139))
      return 2;
    uint64_t object = native(MEMORY_OBJECT_CREATE, 8192, 0, 0, 0, 0, 0);
    if ((int64_t)object < 0) return 3;
    if (native(MEMORY_OBJECT_LENGTH, object, 0, 0, 0, 0, 0) != 8192) return 35;
    fprintf(stderr, "shared-memory: created\n");
    uint64_t first = map(object, 8192, READ | WRITE, 0);
    uint64_t second = map(object, 4096, READ | WRITE, 4096);
    if ((int64_t)first < 0 || (int64_t)second < 0) return 4;
    fprintf(stderr, "shared-memory: mapped\n");
    volatile unsigned char *bytes = (volatile unsigned char *)(uintptr_t)first;
    for (unsigned i = 0; i < 8192; ++i) if (bytes[i] != 0) return 5;
    bytes[4096 + 37] = 0x5b;
    if (((volatile unsigned char *)(uintptr_t)second)[37] != 0x5b) return 6;
    uint64_t private_map = native(MEMORY_MAP, 0, 8192, READ | WRITE, 0, object, 0);
    if ((int64_t)private_map < 0) return 39;
    volatile unsigned char *private_bytes = (volatile unsigned char *)(uintptr_t)private_map;
    if (private_bytes[4096 + 37] != 0x5b) return 40;
    private_bytes[4096 + 37] = 0x61;
    if (bytes[4096 + 37] != 0x5b) return 41;
    /* Reserving virtual space does not grant access to absent backing pages.
       Live backing bounds are enforced by faults, not map-time length. */
    uint64_t future = map(object, 4096, READ, 8192);
    if ((int64_t)future < 0) return 7;
    if (native(MEMORY_UNMAP, future, 4096, 0, 0, 0, 0) != 0) return 44;
    if ((int64_t)map(object, 8192, READ, UINT64_MAX & ~UINT64_C(4095)) != INT64_C(-262143)) return 45;
    if ((int64_t)map(object, 4096, READ | 4, 0) >= 0) return 8;
    if (native(HANDLE_CLOSE, object, 0, 0, 0, 0, 0) != 0) return 9;
    if (private_bytes[4096 + 37] != 0x61) return 42;
    if (native(MEMORY_UNMAP, private_map, 8192, 0, 0, 0, 0) != 0) return 43;
    if (bytes[4096 + 37] != 0x5b) return 10;
    if (native(MEMORY_UNMAP, first, 8192, 0, 0, 0, 0) != 0) return 11;
    if (((volatile unsigned char *)(uintptr_t)second)[37] != 0x5b) return 12;
    if (native(MEMORY_UNMAP, second, 4096, 0, 0, 0, 0) != 0) return 13;
    fprintf(stderr, "shared-memory: local lifetime ok\n");

    uint64_t endpoint = native(IPC_CREATE, 0, 0, 0, 0, 0, 0);
    if ((int64_t)endpoint < 0) return 14;
    if ((int64_t)native(MEMORY_OBJECT_LENGTH, endpoint, 0, 0, 0, 0, 0) != INT64_C(-262138)) return 36;
    pid_t child = fork();
    if (child < 0) return 15;
    fprintf(stderr, "shared-memory: fork %d\n", (int)child);
    if (child == 0) {
        uint64_t memory = native(MEMORY_OBJECT_CREATE, 4096, 0, 0, 0, 0, 0);
        uint64_t address = map(memory, 4096, READ | WRITE, 0);
        fprintf(stderr, "shared-memory: child mapped %lld %lld\n", (long long)memory, (long long)address);
        if ((int64_t)memory < 0 || (int64_t)address < 0) _exit(16);
        ((volatile unsigned char *)(uintptr_t)address)[103] = 0xa7;
        uint64_t reduced = native(HANDLE_DUPLICATE, memory, READ | MAP | DUPLICATE | TRANSFER, 0, 0, 0, 0);
        if ((int64_t)reduced < 0) _exit(17);
        fprintf(stderr, "shared-memory: child reduced\n");
        struct attachments handles = { .count = 1, .handles = {{ (uint32_t)reduced, 0, READ | MAP | WRITE }} };
        unsigned char request = 1, reply = 0;
        int64_t denied = (int64_t)native(IPC_SEND_HANDLES, endpoint, (uintptr_t)&request, 1, (uintptr_t)&handles, 0, 0);
        fprintf(stderr, "shared-memory: attenuation result %lld\n", (long long)denied);
        if (denied != -13) _exit(18);
        handles.handles[0].rights = READ | MAP;
        fprintf(stderr, "shared-memory: sending\n");
        uint64_t result = native(IPC_CALL_HANDLES, endpoint, (uintptr_t)&request, 1, (uintptr_t)&reply, 1, (uintptr_t)&handles);
        if ((int64_t)result < 0 || reply != 2) _exit(19);
        if (native(HANDLE_CLOSE, reduced, 0, 0, 0, 0, 0) != 0) _exit(20);
        if (native(HANDLE_CLOSE, memory, 0, 0, 0, 0, 0) != 0) _exit(21);
        if (native(MEMORY_UNMAP, address, 4096, 0, 0, 0, 0) != 0) _exit(22);
        _exit(0);
    }
    unsigned char request = 0, reply = 2;
    struct attachments handles = {0};
    uint64_t message = native(IPC_RECV_HANDLES, (uintptr_t)&request, 1, (uintptr_t)&handles, endpoint, 0, 0);
    if ((int64_t)message < 0 || request != 1 || handles.count != 1) return 23;
    fprintf(stderr, "shared-memory: received\n");
    uint64_t received = handles.handles[0].handle;
    uint64_t readonly = map(received, 4096, READ, 0);
    if ((int64_t)readonly < 0) return 24;
    if (((volatile unsigned char *)(uintptr_t)readonly)[103] != 0xa7) return 25;
    if ((int64_t)map(received, 4096, READ | WRITE, 0) >= 0) return 26;
    if ((int64_t)native(MEMORY_PROTECT, readonly, 4096, READ | WRITE, 0, 0, 0) >= 0) return 27;
    /* Delivery proof belongs to the kernel's receive envelope, not a send.
       Check rejection before constructing the ordinary outgoing envelope. */
    if (handles.delivery_flags != 2) return 37;
    if ((int64_t)native(IPC_SEND_HANDLES, endpoint, (uintptr_t)&request, 1, (uintptr_t)&handles, 0, 0) != -22) return 38;
    handles.delivery_flags = 0;
    if ((int64_t)native(IPC_SEND_HANDLES, endpoint, (uintptr_t)&request, 1, (uintptr_t)&handles, 0, 0) != -13) return 28;
    if (native(HANDLE_CLOSE, received, 0, 0, 0, 0, 0) != 0) return 29;
    if (native(IPC_REPLY, message >> 32, (uintptr_t)&reply, 1, 0, 0, 0) != 0) return 30;
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) return 31;
    if (((volatile unsigned char *)(uintptr_t)readonly)[103] != 0xa7) return 32;
    if (native(MEMORY_UNMAP, readonly, 4096, 0, 0, 0, 0) != 0) return 33;
    if (native(HANDLE_CLOSE, endpoint, 0, 0, 0, 0, 0) != 0) return 34;
    /* Test both pager paths: absent storage must never become an accessible
       zero page. This checks native process termination, not POSIX SIGBUS
       translation, which is a separate userspace exception-delivery task. */
    uint64_t bounded = native(MEMORY_OBJECT_CREATE, 4096, 0, 0, 0, 0, 0);
    if ((int64_t)bounded < 0) return 46;
    for (unsigned shared = 0; shared < 2; ++shared) {
        pid_t invalid = fork();
        if (invalid < 0) return 47;
        if (invalid == 0) {
            uint64_t absent = native(MEMORY_MAP, 0, 4096, READ,
                                     shared ? SHARED : 0, bounded, 4096);
            if ((int64_t)absent < 0) _exit(48);
            unsigned char value = *(volatile unsigned char *)(uintptr_t)absent;
            (void)value;
            _exit(49); /* Must not reach this after the absent-page read. */
        }
        status = 0;
        if (waitpid(invalid, &status, 0) != invalid || !WIFEXITED(status) || WEXITSTATUS(status) != 255) return 50;
    }
    if (native(HANDLE_CLOSE, bounded, 0, 0, 0, 0, 0) != 0) return 51;
    fprintf(stderr, "shared-memory: aliases, attenuation, IPC, retained mappings ok\n");
    return 0;
}

int main(void) {
    int result = probe();
    char text[96];
    snprintf(text, sizeof(text), "shared-memory: result=%d\n", result);
    native(660, (uintptr_t)text, strlen(text), 0, 0, 0, 0);
    return result;
}
