/* Isolated KVM Input-slot probe. No PID lookup or kernel credentials. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define NATIVE_INVALID_ARGUMENT INT64_C(-262139)
#define NATIVE_INVALID_ADDRESS INT64_C(-262142)
#define NATIVE_ACCESS_DENIED INT64_C(-262138)
#define NATIVE_NOT_FOUND INT64_C(-262135)

enum { IPC_CREATE = 587, EXECUTION_IDENTITY_READ = 677, IPC_ENDPOINT_IDENTITY_READ = 678 };
struct identity { uint64_t process, thread; };
_Static_assert(sizeof(struct identity) == 16, "native execution identity ABI");

struct security_identity {
    uint64_t process, thread;
    uint8_t provenance, reserved0[7], key[32];
    uint16_t package_length, developer_length;
    uint32_t reserved1;
    uint8_t package[128], developer[128];
};
_Static_assert(sizeof(struct security_identity) == 320, "credential-free native security ABI");

static int64_t native3(uint64_t number, uint64_t a, uint64_t b, uint64_t c) {
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return (int64_t)number;
}
#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "endpoint-identity: FAIL line %d\n", __LINE__); \
        return 1; \
    } \
} while (0)

static int64_t native6(uint64_t number, uint64_t a, uint64_t b, uint64_t c,
                       uint64_t d, uint64_t e, uint64_t f) {
    register uint64_t r10 __asm__("r10") = d;
    register uint64_t r8 __asm__("r8") = e;
    register uint64_t r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return (int64_t)number;
}

static int register_signal_thread(void) {
    enum { LAUNCH_HANDLE_GET = 628, IPC_CALL_HANDLES = 632,
           THREAD_HANDLE_CREATE = 656, HANDLE_CLOSE = 626, SIGNAL_THREAD_REGISTER = 37 };
    struct attachment { uint32_t handle, reserved; uint64_t rights; };
    struct attachments { uint32_t count, reserved; struct attachment entries[4]; } handles = {0};
    _Static_assert(sizeof(handles) == 72, "IPC object attachment ABI");
    uint64_t key = 0;
    memcpy(&key, "POSXCTRL", sizeof(key));
    int64_t control = native3(LAUNCH_HANDLE_GET, key, 0, 0);
    int64_t thread = native3(THREAD_HANDLE_CREATE, 0, 0, 0);
    CHECK(control > 0 && thread > 0);
    for (unsigned attempt = 0; attempt < 2; ++attempt) {
        unsigned char request[32] = {0}, response[32] = {0};
        memcpy(request, "POSX", 4);
        request[4] = 1;
        request[6] = SIGNAL_THREAD_REGISTER;
        request[8] = 42 + attempt;
        handles = (struct attachments){0};
        handles.count = 1;
        handles.entries[0].handle = (uint32_t)thread;
        handles.entries[0].rights = attempt ? (1 << 4) | (1 << 5) : (1 << 4);
        int64_t message = native6(IPC_CALL_HANDLES, control, (uint64_t)request, sizeof(request),
                                  (uint64_t)response, sizeof(response), (uint64_t)&handles);
        CHECK(message >= 0 && (uint32_t)message == sizeof(response));
        int32_t status = 0;
        memcpy(&status, response + 24, sizeof(status));
        CHECK(handles.count == 0 && response[8] == request[8]);
        CHECK(status == (attempt ? 0 : -22));
    }
    CHECK(native3(HANDLE_CLOSE, thread, 0, 0) == 0);
    CHECK(native3(HANDLE_CLOSE, control, 0, 0) == 0);
    fprintf(stderr, "endpoint-identity: PASS POSIX signal registration authenticates "
                    "the attached sender thread; reduced rights rejected\n");
    return 0;
}

int main(void) {
    /* Removed credential-spawn ABI must not accept even a null request or
       inspect user pointers through a compatibility shim. */
    CHECK(native6(608, 0, 0, 0, 0, 0, 0) == -38);
    CHECK(native6(608, UINT64_MAX, UINT64_MAX, UINT64_MAX,
                  UINT64_MAX, UINT64_MAX, UINT64_MAX) == -38);
    fprintf(stderr, "endpoint-identity: PASS removed credential spawn returns ENOSYS\n");
    struct identity caller = {0}, endpoint_owner = {0};
    /* Unused argument registers are not part of the two-argument caller ABI. */
    CHECK(native3(EXECUTION_IDENTITY_READ, (uint64_t)&caller, sizeof(caller), UINT64_MAX) == 0);
    CHECK(caller.process && caller.thread);
    int64_t endpoint = native3(IPC_CREATE, 0, 0, 0);
    CHECK(endpoint > 0 && (uint64_t)endpoint != caller.thread);
    struct {
        struct security_identity identity;
        uint64_t guard;
    } security;
    memset(&security, 0x5a, sizeof(security));
    CHECK(native3(617, 0, (uint64_t)&security.identity, sizeof(security.identity) - 1) == NATIVE_INVALID_ARGUMENT);
    for (unsigned i = 0; i < sizeof(security); ++i)
        CHECK(((unsigned char *)&security)[i] == 0x5a);
    CHECK(native3(617, 0, 0, sizeof(security.identity)) == NATIVE_INVALID_ADDRESS);
    CHECK(native3(617, 0, (uint64_t)&security.identity, sizeof(security.identity)) == 0);
    CHECK(security.guard == UINT64_C(0x5a5a5a5a5a5a5a5a));
    CHECK(security.identity.process == caller.process && security.identity.thread == caller.thread);
    CHECK(security.identity.provenance == 1);
    CHECK(security.identity.package_length == sizeof("org.mochios.input") - 1);
    CHECK(memcmp(security.identity.package, "org.mochios.input", security.identity.package_length) == 0);
#ifdef EXPECT_INSPECTION_DENIED
    CHECK(native3(617, endpoint, (uint64_t)&security.identity, sizeof(security.identity)) == NATIVE_ACCESS_DENIED);
#endif
    fprintf(stderr, "endpoint-identity: PASS credential-free security identity, "
                    "exact-size output, package authentication and inspection gate\n");
    memset(&endpoint_owner, 0x5a, sizeof(endpoint_owner));
    struct identity unchanged = endpoint_owner;
    CHECK(native3(IPC_ENDPOINT_IDENTITY_READ, (uint64_t)&endpoint_owner,
                  sizeof(endpoint_owner) - 1, endpoint) == NATIVE_INVALID_ARGUMENT);
    CHECK(memcmp(&endpoint_owner, &unchanged, sizeof(unchanged)) == 0);
#ifdef EXPECT_INSPECTION_DENIED
    CHECK(native3(IPC_ENDPOINT_IDENTITY_READ, (uint64_t)&endpoint_owner,
                  sizeof(endpoint_owner), endpoint) == NATIVE_ACCESS_DENIED);
    CHECK(memcmp(&endpoint_owner, &unchanged, sizeof(unchanged)) == 0);
    CHECK(native3(IPC_ENDPOINT_IDENTITY_READ, (uint64_t)&endpoint_owner,
                  sizeof(endpoint_owner), UINT64_MAX) == NATIVE_ACCESS_DENIED);
    fprintf(stderr, "endpoint-identity: PASS caller identity without inspection; "
                    "endpoint inspection denied; malformed size leaves output untouched\n");
#else
    CHECK(native3(IPC_ENDPOINT_IDENTITY_READ, (uint64_t)&endpoint_owner,
                  sizeof(endpoint_owner), endpoint) == 0);
    CHECK(endpoint_owner.process == caller.process && endpoint_owner.thread == caller.thread);
    CHECK(native3(IPC_ENDPOINT_IDENTITY_READ, 0, sizeof(endpoint_owner), endpoint) == NATIVE_INVALID_ADDRESS);
    memset(&endpoint_owner, 0x5a, sizeof(endpoint_owner));
    CHECK(native3(IPC_ENDPOINT_IDENTITY_READ, (uint64_t)&endpoint_owner,
                  sizeof(endpoint_owner), UINT64_MAX) == NATIVE_NOT_FOUND);
    CHECK(memcmp(&endpoint_owner, &unchanged, sizeof(unchanged)) == 0);
    CHECK(native3(IPC_ENDPOINT_IDENTITY_READ, (uint64_t)&endpoint_owner,
                  sizeof(endpoint_owner), caller.thread) == NATIVE_NOT_FOUND);
    CHECK(memcmp(&endpoint_owner, &unchanged, sizeof(unchanged)) == 0);
    fprintf(stderr, "endpoint-identity: PASS inspected endpoint matches native caller; "
                    "raw TID and invalid endpoint rejected; invalid output rejected\n");
#endif
    return register_signal_thread();
}
