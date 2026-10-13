/* Tests real named-object IPC before the public sem_open mapping cache lands. */
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct header {
    char magic[4]; uint16_t version, opcode; uint64_t request;
    uint32_t flags, length; int32_t status; uint32_t reserved;
};
struct attachment { uint32_t handle, reserved; uint64_t rights; };
struct handles { uint32_t count, flags; struct attachment entries[4]; };
_Static_assert(sizeof(struct header) == 32, "POSIX header ABI");
_Static_assert(sizeof(struct handles) == 72, "native attachments ABI");
#define RIGHTS (UINT64_C(3) | (UINT64_C(1) << 6) | (UINT64_C(3) << 62))
static uint64_t call(uint64_t number, uint64_t a, uint64_t b, uint64_t c,
                     uint64_t d, uint64_t e, uint64_t f) {
    register uint64_t r10 __asm__("r10") = d;
    register uint64_t r8 __asm__("r8") = e;
    register uint64_t r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "+a"(number)
        : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return number;
}
static void debug(const char *text) { call(660, (uintptr_t)text, strlen(text), 0, 0, 0, 0); }
#define CHECK(x) do { if (!(x)) { char text[128]; snprintf(text, sizeof(text), "native-named-semaphore: FAIL line=%u\n", __LINE__); debug(text); return 1; } } while (0)
static int request(uint64_t endpoint, uint16_t opcode, uint32_t options, uint32_t value,
                   struct handles *handles, struct header *response) {
    const char *name = "/native-named-gate";
    unsigned char bytes[128] = {0};
    struct header header = {{'P','O','S','X'}, 1, opcode, 123, 0, 0, 0, 0};
    uint32_t length = (uint32_t)strlen(name);
    uint32_t fields[4] = { options, options ? 0600 : 0, value, length };
    if (opcode == 74) {
        header.length = 16 + length;
        memcpy(bytes + 32, fields, 16); memcpy(bytes + 48, name, length);
    } else {
        header.length = 4 + length;
        memcpy(bytes + 32, &length, 4); memcpy(bytes + 36, name, length);
    }
    memcpy(bytes, &header, 32);
    uint64_t result = call(632, endpoint, (uintptr_t)bytes, 32 + header.length,
                           (uintptr_t)response, sizeof(*response), (uintptr_t)handles);
    if ((int64_t)result < 0 || (uint32_t)result != 32 || response->request != 123
        || memcmp(response->magic, "POSX", 4) || response->version != 1
        || response->opcode != 0x8000 || response->length || handles->flags) return -999;
    return response->status;
}
int main(void) {
    uint64_t key; memcpy(&key, "POSXCTRL", 8);
    uint64_t endpoint = call(628, key, 0, 0, 0, 0, 0);
    CHECK((int64_t)endpoint > 0);
    struct handles handles = {0}; struct header response;
    CHECK(request(endpoint, 74, 1 | 2, 7, &handles, &response) == 0);
    CHECK(handles.count == 1 && handles.entries[0].rights == RIGHTS);
    uint32_t first = handles.entries[0].handle;
    CHECK(call(664, first, 0, 0, 0, 0, 0) == RIGHTS);
    memset(&handles, 0, sizeof(handles));
    CHECK(request(endpoint, 74, 0, 0, &handles, &response) == 0 && handles.count == 1);
    uint32_t second = handles.entries[0].handle;
    CHECK(call(666, first, second, 0, 0, 0, 0) == 1);
    memset(&handles, 0, sizeof(handles));
    CHECK(request(endpoint, 74, 1 | 2, 0, &handles, &response) == -17 && handles.count == 0);
    uint64_t address = call(582, 0, 4096, 3, 2, first, 0);
    CHECK((int64_t)address > 0);
    sem_t *semaphore = (sem_t *)(uintptr_t)address;
    int value; CHECK(sem_getvalue(semaphore, &value) == 0 && value == 7);
    memset(&handles, 0, sizeof(handles));
    CHECK(request(endpoint, 75, 0, 0, &handles, &response) == 0 && handles.count == 0);
    CHECK(sem_trywait(semaphore) == 0 && sem_getvalue(semaphore, &value) == 0 && value == 6);
    CHECK(call(626, first, 0, 0, 0, 0, 0) == 0);
    CHECK(call(626, second, 0, 0, 0, 0, 0) == 0);
    CHECK(sem_post(semaphore) == 0 && sem_getvalue(semaphore, &value) == 0 && value == 7);
    memset(&handles, 0, sizeof(handles));
    CHECK(request(endpoint, 74, 0, 0, &handles, &response) == -2 && handles.count == 0);
    memset(&handles, 0, sizeof(handles));
    CHECK(request(endpoint, 74, 1 | 2, 0, &handles, &response) == 0 && handles.count == 1);
    uint32_t fresh = handles.entries[0].handle;
    uint64_t fresh_address = call(582, 0, 4096, 3, 2, fresh, 0);
    CHECK((int64_t)fresh_address > 0);
    CHECK(sem_getvalue((sem_t *)(uintptr_t)fresh_address, &value) == 0 && value == 0);
    CHECK(sem_getvalue(semaphore, &value) == 0 && value == 7);
    memset(&handles, 0, sizeof(handles));
    CHECK(request(endpoint, 75, 0, 0, &handles, &response) == 0);
    CHECK(call(583, address, 4096, 0, 0, 0, 0) == 0);
    CHECK(call(583, fresh_address, 4096, 0, 0, 0, 0) == 0);
    CHECK(call(626, fresh, 0, 0, 0, 0, 0) == 0);
    debug("native-named-semaphore: PASS authenticated IPC, shared object identity, delegated rights, exclusive create, unlink lifetime and independent recreation\n");
    return 0;
}
