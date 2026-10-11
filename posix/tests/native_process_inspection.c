/* Isolated Compositor-slot probe: its existing process.inspect authority is
 * used without changing capability policy or claiming a desktop smoke test. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum { LIST_PROCESSES = 552, EXECUTION_IDENTITY_READ = 677, RECORD_SIZE = 104, MAX_RECORDS = 256 };
static struct { unsigned char records[RECORD_SIZE * MAX_RECORDS]; unsigned char guard[16]; } output;
static int64_t native2(uint64_t number, uint64_t a, uint64_t b) {
    __asm__ volatile("syscall" : "+a"(number) : "D"(a), "S"(b) : "rcx", "r11", "memory");
    return (int64_t)number;
}
#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "process-inspection: FAIL line %d\n", __LINE__); \
        return 1; \
    } \
} while (0)

int main(void) {
    uint64_t identity[2] = {0};
    CHECK(native2(EXECUTION_IDENTITY_READ, (uint64_t)identity, sizeof(identity)) == 0);
    memset(&output, 0xcc, sizeof(output));
    int64_t count = native2(LIST_PROCESSES, (uint64_t)output.records, sizeof(output.records));
    CHECK(count > 0 && count <= MAX_RECORDS);
    for (unsigned i = 0; i < sizeof(output.guard); ++i) CHECK(output.guard[i] == 0xcc);
    int found = 0;
    for (int64_t i = 0; i < count; ++i) {
        unsigned char *record = output.records + i * RECORD_SIZE;
        uint64_t pid, state, memory_bytes, thread_count;
        memcpy(&pid, record, 8);
        if (pid != identity[0]) continue;
        memcpy(&state, record + 16, 8);
        memcpy(&memory_bytes, record + 32, 8);
        memcpy(&thread_count, record + 40, 8);
        CHECK(state == 1 && memory_bytes > 0 && thread_count > 0);
        static const char expected[] = "org.mochios.compositor";
        CHECK(memcmp(record + 48, expected, sizeof(expected)) == 0);
        found = 1;
    }
    CHECK(found);
    fprintf(stderr, "process-inspection: PASS compact records, metrics, identity and output bounds\n");
    return 0;
}
