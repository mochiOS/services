/* Included by the native Handle capture probe: real authenticated POSIX IPC. */
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define FP_CHECK(x) do { if (!(x)) { printf("fork-policy: FAIL line=%d\n", __LINE__); return 0; } } while (0)
static int fp_request(unsigned opcode, uint64_t token, uint32_t object, uint64_t rights,
                      unsigned flags, unsigned payload_length, unsigned char reply[64]) {
    struct { uint32_t count, flags; struct { uint32_t handle, reserved; uint64_t rights; } objects[4]; } handles = {0};
    unsigned char request[40] = {'P','O','S','X',1,0,0,0};
    request[6] = (unsigned char)opcode;
    hc_put64(request + 8, 0xface);
    hc_put32(request + 16, flags); hc_put32(request + 20, payload_length);
    hc_put64(request + 32, token);
    if (object) { handles.count = 1; handles.objects[0].handle = object; handles.objects[0].rights = rights; }
    uint64_t key; memcpy(&key, "POSXCTRL", 8);
    uint64_t endpoint = (uint64_t)HC(628, key, 0, 0);
    uint64_t result = 632;
    register uint64_t r10 __asm__("r10") = (uint64_t)reply;
    register uint64_t r8 __asm__("r8") = 64;
    register uint64_t r9 __asm__("r9") = (uint64_t)&handles;
    __asm__ volatile("syscall" : "+a"(result) : "D"(endpoint), "S"(request), "d"((uint64_t)(32 + payload_length)), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    if ((int64_t)result < 0) {
        printf("fork-policy: transport opcode=%u result=%lld endpoint=%llu\n", opcode, (long long)result, (unsigned long long)endpoint);
        return (int)result;
    }
    /* Native IPC returns (sender endpoint << 32) | received byte length. */
    result &= UINT32_MAX;
    if (result < 32 || result > 64 || memcmp(reply, "POSX\1\0\0\200", 8)
        || hc_get64(reply + 8) != 0xface || hc_get32(reply + 20) != result - 32 || handles.count) {
        printf("fork-policy: invalid reply opcode=%u length=%llu payload=%u objects=%u\n", opcode, (unsigned long long)result, hc_get32(reply + 20), handles.count);
        return -5;
    }
    return (int32_t)hc_get32(reply + 24);
}
static uint64_t fp_begin(mode_t *previous_umask) {
    unsigned char reply[64];
    int first = fp_request(91, 0, 0, 0, 1, 0, reply);
    if (first != -22) printf("fork-policy: invalid flags status=%d\n", first);
    FP_CHECK(first == -22);
    FP_CHECK(fp_request(91, 1, 0, 0, 0, 8, reply) == -22);
    /* Cancellation must release the service's quota, not only client memory. */
    for (unsigned i = 0; i < 70; ++i) {
        FP_CHECK(fp_request(91, 0, 0, 0, 0, 0, reply) == 0 && hc_get32(reply + 20) == 8);
        uint64_t token = hc_get64(reply + 32);
        FP_CHECK(token && fp_request(93, token, 0, 0, 0, 8, reply) == 0);
    }
    *previous_umask = umask(027);
    FP_CHECK(fp_request(91, 0, 0, 0, 0, 0, reply) == 0 && hc_get32(reply + 20) == 8);
    uint64_t token = hc_get64(reply + 32);
    int64_t thread = HC(656, 0, 0, 0);
    FP_CHECK(thread > 0);
    FP_CHECK(fp_request(92, token, (uint32_t)thread, 0x30, 0, 8, reply) == -9);
    FP_CHECK(HC(626, thread, 0, 0) == 0);
    FP_CHECK(umask(077) == 027);
    return token;
}
static int fp_commit(uint64_t token, uint32_t child) {
    unsigned char reply[64];
    FP_CHECK(fp_request(92, token, child, 0x10, 0, 8, reply) == -22);
    FP_CHECK(fp_request(92, 0, child, 0x30, 0, 8, reply) == -22);
    FP_CHECK(fp_request(92, token, child, 0x30, 0, 8, reply) == 0);
    FP_CHECK(fp_request(93, token, 0, 0, 0, 8, reply) == -3);
    FP_CHECK(fp_request(55, 0, child, 0x10, 0, 0, reply) == 0 && hc_get32(reply + 20) == 20);
    FP_CHECK(hc_get32(reply + 48) == 027);
    FP_CHECK(fp_request(3, 0, 0, 0, 0, 0, reply) == 0 && hc_get32(reply + 48) == 077);
    return 1;
}
#undef FP_CHECK
