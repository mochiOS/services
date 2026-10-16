/* Isolated Compositor-slot probe using its existing process.spawn authority.
 * All execution cloning uses newlib's AddressSpaceClone + ProcessCreate path.
 * Immediate source-TLB isolation is covered by native_snapshot_continuation.c. */
#include <stdint.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
extern int native_thread_register_probe(void);

static volatile unsigned char private_value = 0x11;
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
static int64_t native3(uint64_t number, uint64_t a, uint64_t b, uint64_t c) {
    register uint64_t r10 __asm__("r10") = 0;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
    return (int64_t)number;
}
#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "clone-cow: FAIL line %d\n", __LINE__); \
        return 1; \
    } \
} while (0)

int main(void) {
    CHECK(native3(644 /* removed combined-clone ABI */, 0, 0, 0) == -38);
    enum { CLOSE = 626, SPACE_CLONE = 679, RIGHTS_GET = 664,
           DUPLICATE = 627, SAME_OBJECT = 666, MEMORY_OBJECT_CREATE = 671, MEMORY_MAP = 582 };
    struct status { uint64_t id; uint32_t state, reserved; uint64_t code; } status;
    const uint64_t control = UINT64_C(1) << 8;
    const uint64_t duplicate = UINT64_C(1) << 62;
    const uint64_t transfer = UINT64_C(1) << 63;
    for (unsigned attempt = 0; attempt < 12; ++attempt) {
        int64_t image = native3(SPACE_CLONE, 0, 0, 0);
        CHECK(image > 0);
        CHECK((uint64_t)native3(RIGHTS_GET, image, 0, 0)
              == (control | duplicate | transfer));
        CHECK(native3(DUPLICATE, image, 1 /* READ */, 0) == INT64_C(-262138));
        int64_t copy = native3(DUPLICATE, image, control, 0);
        CHECK(copy > 0);
        CHECK(native3(SAME_OBJECT, image, copy, 0) == 1);
        CHECK(native3(642 /* ProcessHandleStatus */, image, (uint64_t)&status, 0) == INT64_C(-262138));
        CHECK(native3(CLOSE, image, 0, 0) == 0);
        CHECK(native3(RIGHTS_GET, copy, 0, 0) == (int64_t)control);
        private_value = 0x22;
        CHECK(native3(CLOSE, copy, 0, 0) == 0);
        CHECK(native3(RIGHTS_GET, copy, 0, 0) == -9);
    }
    fprintf(stderr, "address-space-image: PASS detached images close and attenuate without process authority\n");
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        _exit(37);
    }
    int exit_status = 0;
    CHECK(waitpid(child, &exit_status, 0) == child);
    CHECK(WIFEXITED(exit_status) && WEXITSTATUS(exit_status) == 37);
    fprintf(stderr, "clone-resume: PASS newlib fork selects zero in the child and waitpid reaps it\n");
    pid_t children[4];
    for (unsigned index = 0; index < 4; ++index) {
        child = fork();
        CHECK(child >= 0);
        if (child == 0) _exit((int)index + 5);
        children[index] = child;
    }
    for (unsigned index = 0; index < 4; ++index) {
        CHECK(waitpid(children[index], &exit_status, 0) == children[index]);
        CHECK(WIFEXITED(exit_status) && WEXITSTATUS(exit_status) == (int)index + 5);
    }
    fprintf(stderr, "native-fork: PASS removed clone ABI rejects calls; explicit creation supports concurrent children\n");
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        int channel[2];
        CHECK(pipe(channel) == 0);
        int writer = dup(channel[1]);
        CHECK(writer >= 0);
        CHECK(fcntl(writer, F_SETFD, FD_CLOEXEC) == 0);
        private_value = 0x11;
        child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            if (private_value != 0x11 || close(channel[0]) != 0 ||
                close(channel[1]) != 0 || fcntl(writer, F_GETFD) != FD_CLOEXEC)
                _exit(91);
            pid_t grandchild = fork();
            if (grandchild < 0) _exit(92);
            if (grandchild == 0) {
                const unsigned char marker = 0x37;
                if (write(writer, &marker, 1) != 1 || close(writer) != 0)
                    _exit(93);
                _exit(38);
            }
            int nested_status = 0;
            if (waitpid(grandchild, &nested_status, 0) != grandchild ||
                !WIFEXITED(nested_status) || WEXITSTATUS(nested_status) != 38)
                _exit(94);
            if (close(writer) != 0) _exit(95);
            _exit(39);
        }
        private_value = 0x22;
        CHECK(close(channel[1]) == 0);
        CHECK(close(writer) == 0);
        unsigned char marker = 0;
        CHECK(read(channel[0], &marker, 1) == 1 && marker == 0x37);
        CHECK(waitpid(child, &exit_status, 0) == child);
        CHECK(WIFEXITED(exit_status) && WEXITSTATUS(exit_status) == 39);
        CHECK(read(channel[0], &marker, 1) == 0);
        CHECK(close(channel[0]) == 0);
        CHECK(private_value == 0x22);
    }
    fprintf(stderr, "native-fork: PASS repeated nested fork inherits pipe/dup/CLOEXEC descriptors and independent closes\n");
    int source = open("/system/services/compositor.service", O_RDONLY);
    CHECK(source >= 0);
    int alias = dup(source);
    CHECK(alias >= 0);
    CHECK(lseek(source, 0, SEEK_SET) == 0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        unsigned char signature[3];
        if (close(source) != 0 || lseek(alias, 1, SEEK_SET) != 1 ||
            read(alias, signature, sizeof(signature)) != sizeof(signature) ||
            signature[0] != 'E' || signature[1] != 'L' || signature[2] != 'F' ||
            close(alias) != 0)
            _exit(96);
        _exit(40);
    }
    CHECK(waitpid(child, &exit_status, 0) == child);
    CHECK(WIFEXITED(exit_status) && WEXITSTATUS(exit_status) == 40);
    CHECK(lseek(source, 0, SEEK_CUR) == 4);
    CHECK(lseek(alias, 0, SEEK_CUR) == 4);
    volatile unsigned char *private_map = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                               MAP_PRIVATE, source, 0);
    CHECK(private_map != MAP_FAILED && private_map[0] == 0x7f);
    volatile unsigned char *shared_map = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                              MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(shared_map != MAP_FAILED);
    shared_map[0] = 0x21;
    int64_t memory = native3(MEMORY_OBJECT_CREATE, 4096, 0, 0);
    CHECK(memory > 0);
    int64_t allocated = native6(MEMORY_MAP, 0, 4096, 3, 2, (uint64_t)memory, 0);
    CHECK(allocated > 0);
    CHECK(native3(CLOSE, (uint64_t)memory, 0, 0) == 0);
    volatile unsigned char *allocated_map = (void *)(uintptr_t)allocated;
    allocated_map[0] = 0x21;
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        if (private_map[0] != 0x7f || shared_map[0] != 0x21 ||
            allocated_map[0] != 0x21) _exit(97);
        /* A kernel copy into a still-COW destination must isolate it too,
         * without moving the shared open-file description's offset. */
        if (pread(source, (void *)private_map, 1, 0) != 1 ||
            private_map[0] != 0x7f || lseek(source, 0, SEEK_CUR) != 4) _exit(96);
        private_map[0] = 0x5a;
        shared_map[0] = 0x3c;
        allocated_map[0] = 0x6d;
        _exit(private_map[0] == 0x5a ? 42 : 98);
    }
    CHECK(waitpid(child, &exit_status, 0) == child);
    CHECK(WIFEXITED(exit_status) && WEXITSTATUS(exit_status) == 42);
    CHECK(private_map[0] == 0x7f && shared_map[0] == 0x3c && allocated_map[0] == 0x6d);
    CHECK(munmap((void *)private_map, 4096) == 0);
    CHECK(munmap((void *)shared_map, 4096) == 0);
    CHECK(munmap((void *)allocated_map, 4096) == 0);
    CHECK(close(alias) == 0 && close(source) == 0);
    fprintf(stderr, "native-fork: PASS parent/child and dup aliases share the same file offset\n");
    fprintf(stderr, "native-fork: PASS file-backed private COW, anonymous shared mappings and handle-owned RAM\n");
    fprintf(stderr, "native-fork: PASS kernel usercopy isolates a private file-backed COW destination\n");
    int thread_result = native_thread_register_probe();
    if (thread_result != 0) fprintf(stderr, "thread-registers: FAIL case %d\n", thread_result);
    CHECK(thread_result == 0);
    fprintf(stderr, "thread-registers: PASS all explicit registers, TLS and safe flags at native entry\n");
    fprintf(stderr, "thread-registers: PASS newlib pthread_create and pthread_join preserve argument/result\n");
    return 0;
}
