/* Native integration probe; install in the isolated Compositor test slot.
 * Needs fs.read.all, process.spawn, ipc.client and ipc.server. This is not a
 * host executable. argv[1] may override the executable's installed pathname.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {
    CLOSE = 626,
    CONTEXT_GET = 628,
    CREATE_ENDPOINT = 629,
    SEND = 630,
    RECEIVE = 631,
    CONTEXT_SET = 648,
    PAIR = 649,
    CURRENT_THREAD = 656,
    THREAD_STATUS = 658,
    WRITE = 675
};
#define NOT_FOUND INT64_C(-262135)
#define NOT_READY INT64_C(-262137)
#define PEER_CLOSED INT64_C(-262134)
#define ENDPOINT_KEY UINT64_C(0x696d676970630001)
#define WRITER_KEY UINT64_C(0x696d676970630002)
#define THREAD_KEY UINT64_C(0x696d676970630003)
#define CHECK(x)                                                               \
    do {                                                                       \
        if (!(x)) {                                                            \
            fprintf(stderr, "exec-ipc-generation: FAIL line=%d errno=%d\n",    \
                    __LINE__, errno);                                          \
            return 1;                                                          \
        }                                                                      \
    } while (0)

struct item {
    uint32_t handle, reserved;
    uint64_t rights;
};
struct attachments {
    uint32_t count, flags;
    struct item items[4];
};
struct thread_status {
    uint64_t thread_id, process_id;
    uint32_t state, reserved;
};
_Static_assert(sizeof(struct attachments) == 72, "IPC object ABI");
_Static_assert(sizeof(struct thread_status) == 24, "native thread status ABI");

static int64_t native(uint64_t number, uint64_t a, uint64_t b, uint64_t c,
                      uint64_t d) {
    register uint64_t fourth __asm__("r10") = d;
    __asm__ volatile("syscall"
                     : "+a"(number)
                     : "D"(a), "S"(b), "d"(c), "r"(fourth)
                     : "rcx", "r11", "memory");
    return (int64_t)number;
}

static int64_t send(uint64_t endpoint, struct attachments *objects) {
    const char byte = 'G';
    return native(SEND, endpoint, (uintptr_t)&byte, 1, (uintptr_t)objects);
}

static int64_t receive(char *byte, struct attachments *objects) {
    /* Zero selects this thread's nonblocking inbox: no broken test may park
     * forever waiting for a message which image replacement should discard. */
    return native(RECEIVE, (uintptr_t)byte, 1, (uintptr_t)objects, 0);
}

static int replacement(const char *expected_identity) {
    int64_t old = native(CONTEXT_GET, ENDPOINT_KEY, 0, 0, 0);
    int64_t writer = native(CONTEXT_GET, WRITER_KEY, 0, 0, 0);
    int64_t thread = native(CONTEXT_GET, THREAD_KEY, 0, 0, 0);
    CHECK(old > 0 && writer > 0 && thread > 0);
    struct thread_status before = {0}, now = {0};
    CHECK(native(THREAD_STATUS, thread, (uintptr_t)&before, sizeof(before),
                 0) == 0);
    CHECK(before.thread_id == strtoull(expected_identity, NULL, 10));
    int64_t current = native(CURRENT_THREAD, 0, 0, 0, 0);
    CHECK(current > 0);
    CHECK(native(THREAD_STATUS, current, (uintptr_t)&now, sizeof(now), 0) == 0);
    CHECK(now.thread_id == before.thread_id &&
          now.process_id == before.process_id);
    struct attachments objects = {0};
    CHECK(send(old, &objects) == NOT_FOUND);
    char byte = 0;
    CHECK(receive(&byte, &objects) == NOT_READY);
    /* The queued attachment was the last reader reference. Merely hiding its
     * message without releasing the reference would leave this write alive. */
    CHECK(native(WRITE, writer, (uintptr_t) "x", 1, 0) == PEER_CLOSED);
    int64_t fresh = native(CREATE_ENDPOINT, 0, 0, 0, 0);
    CHECK(fresh > 0 && fresh != old);
    CHECK(send(fresh, &objects) == 0);
    int64_t received = receive(&byte, &objects);
    CHECK(received >= 0 && (uint32_t)received == 1 && byte == 'G' &&
          objects.count == 0);
    CHECK(send(old, &objects) == NOT_FOUND);
    CHECK(native(CLOSE, fresh, 0, 0, 0) == 0);
    CHECK(native(CLOSE, old, 0, 0, 0) == 0);
    CHECK(native(CLOSE, writer, 0, 0, 0) == 0);
    CHECK(native(CLOSE, thread, 0, 0, 0) == 0);
    CHECK(native(CLOSE, current, 0, 0, 0) == 0);
    puts("exec-ipc-generation: PASS native thread identity preserved, old "
         "endpoint revoked, queued attachment released, new inbox usable");
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "--verify-ipc-image"))
        return replacement(argv[2]);
    const char *path =
        argc == 2 ? argv[1] : "/system/services/compositor.service";
    int64_t endpoint = native(CREATE_ENDPOINT, 0, 0, 0, 0);
    int64_t thread = native(CURRENT_THREAD, 0, 0, 0, 0);
    CHECK(endpoint > 0 && thread > 0);
    struct thread_status identity = {0};
    CHECK(native(THREAD_STATUS, thread, (uintptr_t)&identity, sizeof(identity),
                 0) == 0);
    uint32_t pair[2] = {0};
    CHECK(native(PAIR, (uintptr_t)pair, 0, 0, 0) == 0);
    CHECK(pair[0] && pair[1] && pair[0] != pair[1]);
    struct attachments objects = {0};
    objects.count = 1;
    objects.items[0].handle = pair[0];
    objects.items[0].rights = 1; /* READ only, no re-delegation. */
    CHECK(send(endpoint, &objects) == 0);
    CHECK(native(CLOSE, pair[0], 0, 0, 0) == 0);
    CHECK(native(CONTEXT_SET, ENDPOINT_KEY, endpoint, 0, 0) == 0);
    CHECK(native(CONTEXT_SET, WRITER_KEY, pair[1], 0, 0) == 0);
    CHECK(native(CONTEXT_SET, THREAD_KEY, thread, 0, 0) == 0);
    char identity_text[24];
    snprintf(identity_text, sizeof(identity_text), "%llu",
             (unsigned long long)identity.thread_id);
    char *arguments[] = {"exec-ipc-generation", "--verify-ipc-image",
                         identity_text, NULL};
    char *environment[] = {NULL};
    /* Failure must leave both the endpoint and the queued attachment intact. */
    CHECK(execve("/system/services/missing-ipc-image-probe", arguments,
                 environment) == -1);
    objects = (struct attachments){0};
    char byte = 0;
    int64_t received = receive(&byte, &objects);
    CHECK(received >= 0 && (uint32_t)received == 1 && byte == 'G');
    CHECK(objects.count == 1 && objects.items[0].rights == 1);
    CHECK(native(WRITE, pair[1], (uintptr_t) "x", 1, 0) == 1);
    /* Requeue the received reader. READ-only references cannot transfer, so
     * use a new pair rather than accidentally testing authority bypass. */
    CHECK(native(CLOSE, objects.items[0].handle, 0, 0, 0) == 0);
    CHECK(native(CLOSE, pair[1], 0, 0, 0) == 0);
    CHECK(native(PAIR, (uintptr_t)pair, 0, 0, 0) == 0);
    objects = (struct attachments){0};
    objects.count = 1;
    objects.items[0].handle = pair[0];
    objects.items[0].rights = 1;
    CHECK(send(endpoint, &objects) == 0);
    CHECK(native(CLOSE, pair[0], 0, 0, 0) == 0);
    CHECK(native(CONTEXT_SET, WRITER_KEY, pair[1], 0, 0) == 0);
    execve(path, arguments, environment);
    fprintf(stderr, "exec-ipc-generation: FAIL exec errno=%d\n", errno);
    return 1;
}
