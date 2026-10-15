/* KVM integration: immutable grants, same-slot reuse, authority attenuation
 * and ProcessCreate using the captured table rather than the caller's table. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct hc_context { uint64_t entry, stack, argument, tls, flags, reserved[3], registers[14]; };
struct hc_status { uint64_t pid; uint32_t state, reserved; uint64_t code; };
extern uint64_t mochios_posix_capture_snapshot(struct hc_context *, uint64_t, uint64_t (*)(void))
    __attribute__((returns_twice));
static int64_t hc_native(uint64_t number, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e) {
    register uint64_t r10 __asm__("r10") = d;
    register uint64_t r8 __asm__("r8") = e;
    __asm__ volatile("syscall" : "+a"(number) : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8)
        : "rcx", "r11", "memory");
    return (int64_t)number;
}
#define HC(n,a,b,c) hc_native(n,(uint64_t)(a),(uint64_t)(b),(uint64_t)(c),0,0)
#define CHECK(x) do { if (!(x)) { printf("native-handle-capture: FAIL line=%d\n", __LINE__); return 1; } } while (0)
static void hc_put32(void *p, uint32_t value) { memcpy(p, &value, 4); }
static void hc_put64(void *p, uint64_t value) { memcpy(p, &value, 8); }
static uint32_t hc_get32(const void *p) { uint32_t value; memcpy(&value, p, 4); return value; }
static uint64_t hc_get64(const void *p) { uint64_t value; memcpy(&value, p, 8); return value; }
#include "native_fork_policy.h"
static const char hc_path[] = "/system/services/compositor.service";
static const char hc_label[] = "captured-handles-child";
static int hc_authorize(uint64_t endpoint) {
    unsigned char request[12 + sizeof(hc_path) - 1] = {0}, reply[8192] = {0};
    hc_put32(request, 0x43414553);
    hc_put64(request + 4, 3); /* Same unprivileged request as newlib fork. */
    memcpy(request + 12, hc_path, sizeof(hc_path) - 1);
    int64_t result = hc_native(588, endpoint, (uint64_t)request, sizeof(request), (uint64_t)reply, sizeof(reply));
    return result >= 12 && hc_get64(reply) == 0;
}
static uint64_t hc_capture_vm(void) { return (uint64_t)HC(679, 0, 0, 0); }
static size_t hc_creation(unsigned char *bytes, const struct hc_context *context,
                          uint32_t capture, uint32_t source, uint64_t rights, unsigned handles) {
    size_t offset = 40 + sizeof(hc_path) - 1 + sizeof(hc_label) - 1;
    memset(bytes, 0, 512);
    memcpy(bytes, "MCRT", 4); bytes[4] = 3; bytes[6] = 40;
    hc_put32(bytes + 8, sizeof(hc_path) - 1); hc_put32(bytes + 12, sizeof(*context));
    hc_put32(bytes + 16, handles); hc_put32(bytes + 24, sizeof(hc_label) - 1);
    hc_put32(bytes + 28, 1); hc_put32(bytes + 32, capture);
    memcpy(bytes + 40, hc_path, sizeof(hc_path) - 1);
    memcpy(bytes + 40 + sizeof(hc_path) - 1, hc_label, sizeof(hc_label) - 1);
    memcpy(bytes + offset, context, sizeof(*context)); offset += sizeof(*context);
    if (handles) {
        hc_put64(bytes + offset, 71); hc_put32(bytes + offset + 8, source);
        hc_put32(bytes + offset + 12, 37); hc_put64(bytes + offset + 16, rights);
        offset += 24;
    }
    return offset;
}
int main(void) {
    _Static_assert(sizeof(struct hc_context) == 176, "native continuation layout");
    const uint64_t read = 1, write = 2, control = UINT64_C(1) << 8;
    const uint64_t duplicate = UINT64_C(1) << 62, transfer = UINT64_C(1) << 63;
    int64_t memory = HC(671, 4096, 0, 0);
    CHECK(memory > 0);
    CHECK(hc_native(674, memory, (uint64_t)"old", 3, 0, 0) == 3);
    int64_t source = HC(627, memory, read | transfer, 0);
    CHECK(source > 0);
    int64_t capture = HC(693, 0, 0, 0);
    CHECK(capture > 0);
    CHECK((uint64_t)HC(664, capture, 0, 0) == (read | control | duplicate));
    CHECK(HC(627, capture, transfer, 0) == -13);
    CHECK(hc_native(674, capture, (uint64_t)"x", 1, 0, 0) == -13);
    unsigned char header[16], record[16];
    CHECK(hc_native(673, capture, (uint64_t)header, 16, 0, 0) == 16);
    CHECK(hc_get32(header) == 1 && hc_get32(header + 8) == 16 && hc_get32(header + 12) == 0);
    unsigned count = hc_get32(header + 4), found = 0;
    CHECK(count > 0 && count <= 4096);
    for (unsigned i = 0; i < count; ++i) {
        CHECK(hc_native(673, capture, (uint64_t)record, 16, 16 + 16 * (uint64_t)i, 0) == 16);
        CHECK(hc_get32(record) != (uint32_t)capture && hc_get32(record + 4) == 0);
        if (hc_get32(record) == (uint32_t)source) {
            CHECK(hc_get64(record + 8) == (read | transfer)); found = 1;
        }
    }
    CHECK(found && hc_native(673, capture, (uint64_t)record, 16, 16 + 16 * (uint64_t)count, 0) == 0);
    int64_t readonly = HC(627, capture, read, 0);
    int64_t delegation = HC(627, capture, control, 0);
    CHECK(readonly > 0 && delegation > 0 && HC(666, capture, readonly, 0) == 1);
    CHECK(hc_native(673, delegation, (uint64_t)header, 16, 0, 0) == -13);
    int64_t nested = HC(693, 0, 0, 0); CHECK(nested > 0);
    CHECK(HC(626, source, 0, 0) == 0 && HC(626, memory, 0, 0) == 0);
    int64_t replacement = -1;
    for (unsigned i = 0; i < 4096; ++i) {
        replacement = HC(671, 4096, 0, 0); CHECK(replacement > 0);
        if (replacement == source) break;
        CHECK(HC(626, replacement, 0, 0) == 0);
        replacement = -1;
    }
    CHECK(replacement == source);
    CHECK(hc_native(674, replacement, (uint64_t)"new", 3, 0, 0) == 3);
    int64_t authority = HC(518, "capability.service", strlen("capability.service"), 0);
    CHECK(authority > 0);
    mode_t previous_umask;
    uint64_t fork_policy = fp_begin(&previous_umask);
    CHECK(fork_policy != 0);
    uint64_t tls; __asm__ volatile("movq %%fs:0,%0" : "=r"(tls));
    struct hc_context context = {0};
    uint64_t image = mochios_posix_capture_snapshot(&context, tls, hc_capture_vm);
    if (image == 0) {
        char data[3];
        int ok = hc_native(673, 37, (uint64_t)data, 3, 0, 0) == 3 && memcmp(data, "old", 3) == 0;
        ok = ok && HC(664, 37, 0, 0) == (int64_t)read;
        ok = ok && hc_native(674, 37, (uint64_t)"x", 1, 0, 0) == -13;
        HC(574, ok ? 37 : 99, 0, 0); __builtin_unreachable();
    }
    CHECK((int64_t)image > 0);
    unsigned char bytes[512];
    const struct { uint32_t table, source; uint64_t rights; unsigned handles; int error; } failures[] = {
        {(uint32_t)readonly,(uint32_t)source,read,1,-13},
        {(uint32_t)image,(uint32_t)source,read,1,-22},
        {UINT32_MAX,(uint32_t)source,read,1,-9},
        {(uint32_t)capture,(uint32_t)source,write,1,-13},
        {(uint32_t)capture,UINT32_MAX,read,1,-9},
        {(uint32_t)nested,(uint32_t)capture,0,1,-13},
        {(uint32_t)readonly,0,0,0,-13},
    };
    for (unsigned i = 0; i < sizeof(failures)/sizeof(failures[0]); ++i) {
        size_t length = hc_creation(bytes, &context, failures[i].table, failures[i].source, failures[i].rights, failures[i].handles);
        CHECK(hc_authorize(authority));
        int64_t result = HC(676, image, bytes, length);
        if (result != failures[i].error) printf("native-handle-capture: case=%u result=%lld\n", i, (long long)result);
        CHECK(result == failures[i].error
            && (uint64_t)HC(664, image, 0, 0) == (control | duplicate | transfer));
    }
    size_t length = hc_creation(bytes, &context, (uint32_t)delegation, (uint32_t)source, read, 1);
    CHECK(hc_authorize(authority));
    int64_t child = HC(676, image, bytes, length); CHECK(child > 0);
    CHECK(fp_commit(fork_policy, (uint32_t)child));
    CHECK(HC(626, image, 0, 0) == 0);
    CHECK(HC(626, capture, 0, 0) == 0 && HC(626, readonly, 0, 0) == 0);
    CHECK(HC(626, delegation, 0, 0) == 0 && HC(626, nested, 0, 0) == 0);
    CHECK(HC(626, replacement, 0, 0) == 0);
    CHECK(HC(645, child, 0, 0) == 0);
    struct hc_status status = {0};
    CHECK(HC(643, child, UINT64_MAX, &status) == 0 && status.state == 2 && status.code == 37);
    int wait_status = 0;
    CHECK(waitpid((pid_t)status.pid, &wait_status, 0) == (pid_t)status.pid
        && WIFEXITED(wait_status) && WEXITSTATUS(wait_status) == 37);
    CHECK(umask(previous_umask) == 077);
    CHECK(HC(626, child, 0, 0) == 0);
    puts("native-handle-capture: PASS stable captured grants after same-slot reuse, CONTROL/TRANSFER checks, rights attenuation and child lifetime");
    puts("fork-policy: PASS authenticated prepare/cancel, ProcessHandle validation and prepared policy committed before child resume");
    return 0;
}
