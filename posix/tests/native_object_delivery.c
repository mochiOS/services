/* Isolated KVM probe: untrusted IPC must not invoke provider object IDs. */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "native-object-delivery: FAIL line %d\n", __LINE__); return 1; } } while (0)
#define NATIVE_INVALID_ARGUMENT INT64_C(-262139)

struct provider_request {
    char magic[4]; uint16_t version, opcode;
    uint64_t object; int64_t argument; uint64_t basis;
    uint32_t length, data_length; uint64_t reserved;
};
struct provider_response {
    char magic[4]; uint16_t version, opcode;
    int64_t status; uint64_t object, value; uint32_t length, reserved;
};
struct handles { uint32_t count, flags; uint64_t items[8]; };
struct filesystem_header {
    char magic[4]; uint16_t version, opcode;
    uint64_t request, mount, node, open, offset;
    uint32_t length, flags; int32_t status; uint32_t mode;
};
_Static_assert(sizeof(struct filesystem_header) == 64, "filesystem header ABI");
_Static_assert(sizeof(struct provider_request) == 48, "provider request ABI");
_Static_assert(sizeof(struct provider_response) == 40, "provider response ABI");
_Static_assert(sizeof(struct handles) == 72, "IPC attachment ABI");

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

static int object_delivery_probe(void) {
    const char *name = "filesystem.service";
    uint64_t endpoint = call(518, (uintptr_t)name, strlen(name), 0, 0, 0, 0);
    CHECK(endpoint != 0 && (int64_t)endpoint >= 0);
    struct provider_request request = {{'M','N','U','P'}, 1, 1, 1, 0, 0, 16, 0, 0};
    struct provider_response response = {0};
    struct handles handles = {0};
    /* User payloads cannot set the receiver-only native-object proof. */
    handles.flags = 1;
    CHECK((int64_t)call(632, endpoint, (uintptr_t)&request, sizeof(request),
          (uintptr_t)&response, sizeof(response), (uintptr_t)&handles) == NATIVE_INVALID_ARGUMENT);
    handles.flags = 2;
    CHECK((int64_t)call(632, endpoint, (uintptr_t)&request, sizeof(request),
          (uintptr_t)&response, sizeof(response), (uintptr_t)&handles) == NATIVE_INVALID_ARGUMENT);
    handles.flags = 0;
    /* Even a valid provider request with a plausible object ID has no authority. */
    uint64_t result = call(632, endpoint, (uintptr_t)&request, sizeof(request),
                           (uintptr_t)&response, sizeof(response), (uintptr_t)&handles);
    CHECK((int64_t)result >= 0 && (uint32_t)result == sizeof(response));
    CHECK(response.status == -13 && handles.flags == 0 && handles.count == 0);
    request.opcode = 4; request.length = 0;
    result = call(632, endpoint, (uintptr_t)&request, sizeof(request),
                  (uintptr_t)&response, sizeof(response), (uintptr_t)&handles);
    CHECK((int64_t)result >= 0 && response.status == -13);
    /* Legacy close/read IDs cannot bypass native object enforcement either. */
    struct filesystem_header control = {{'M','F','S','1'}, 1, 5, 91, 1, 1, 1, 0, 0, 0, 0, 0};
    struct filesystem_header denied = {0};
    result = call(632, endpoint, (uintptr_t)&control, sizeof(control),
                  (uintptr_t)&denied, sizeof(denied), (uintptr_t)&handles);
    CHECK((int64_t)result >= 0 && denied.status == -13 && denied.request == 91);
    control.opcode = 6;
    result = call(588, endpoint, (uintptr_t)&control, sizeof(control),
                  (uintptr_t)&denied, sizeof(denied), 0);
    CHECK((int64_t)result >= 0 && denied.status == -13);
    /* Genuine FileHandle dispatch and kernel-originated release still work. */
    const char *path = "/tmp/native-object-delivery-probe";
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(fd >= 0);
    CHECK(write(fd, "authorized", 10) == 10);
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    char data[16] = {0};
    CHECK(read(fd, data, sizeof(data)) == 10 && memcmp(data, "authorized", 10) == 0);
    CHECK(unlink(path) == 0);
    CHECK(lseek(fd, 0, SEEK_SET) == 0 && read(fd, data, sizeof(data)) == 10);
    CHECK(close(fd) == 0);
    /* Real userspace devfs through ordinary POSIX API and FileHandle fast path. */
    fd = open("/dev/null", O_RDWR);
    CHECK(fd >= 0);
    struct stat metadata;
    CHECK(fstat(fd, &metadata) == 0 && S_ISCHR(metadata.st_mode));
    CHECK(write(fd, "discarded", 9) == 9);
    memset(data, 42, sizeof(data));
    CHECK(read(fd, data, sizeof(data)) == 0 && data[0] == 42);
    CHECK(lseek(fd, 123, SEEK_SET) == 0);
    int duplicate = dup(fd);
    CHECK(duplicate >= 0 && fcntl(duplicate, F_SETFL, O_NONBLOCK) == 0);
    CHECK(fcntl(fd, F_GETFL) & O_NONBLOCK);
    CHECK(close(fd) == 0 && write(duplicate, "alive", 5) == 5);
    CHECK(close(duplicate) == 0);
    fprintf(stderr, "native-devfs: PASS null read/write, metadata, seek and duplicated description flags\n");
    fprintf(stderr, "native-object-delivery: PASS forged flags and raw object-ID requests rejected; native file I/O and unlink lifetime preserved\n");
    return 0;
}

#ifdef WITH_POSIX_REGRESSIONS
int pthread_mutex_probe(void);
int pthread_cond_probe(void);
int posix_regression_main(void);
#endif
int main(void) {
    int result = object_delivery_probe();
#ifdef WITH_POSIX_REGRESSIONS
    if (!result) result = pthread_mutex_probe();
    if (!result) result = pthread_cond_probe();
    if (!result) result = posix_regression_main();
#endif
    return result;
}
