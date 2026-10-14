#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Compile twice with 0/1 and run with matching signed package permissions. */
#ifndef DIAGNOSTIC_AUTHORIZED
#error DIAGNOSTIC_AUTHORIZED must be specified
#endif

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "native-diagnostic-read: FAIL line=%u condition=%s\n",   \
              __LINE__, #condition);                                           \
      return 1;                                                                \
    }                                                                          \
  } while (0)

struct read_result {
  uint64_t next_cursor;
  uint64_t dropped;
};

static const struct read_result read_only = {0};

static int64_t diagnostic_read(uint64_t cursor, void *bytes, uint64_t capacity,
                               struct read_result *metadata) {
  uint64_t result;
  register uint64_t argument3 __asm__("r10") = (uint64_t)metadata;
  __asm__ volatile("syscall"
                   : "=a"(result)
                   : "a"(UINT64_C(687)), "D"(cursor), "S"((uint64_t)bytes),
                     "d"(capacity), "r"(argument3)
                   : "rcx", "r11", "memory");
  return (int64_t)result;
}

int main(void) {
  unsigned char bytes[512];
  struct read_result metadata = {0};
  if (!DIAGNOSTIC_AUTHORIZED) {
    CHECK(diagnostic_read(UINT64_MAX, (void *)UINT64_MAX, UINT64_MAX,
                          (void *)UINT64_MAX) == -13);
    CHECK(diagnostic_read(0, bytes, sizeof(bytes), &metadata) == -13);
    puts("native-diagnostic-read: denied PASS");
    return 0;
  }

  CHECK(sizeof(metadata) == 16);
  CHECK(diagnostic_read(0, bytes, 4097, &metadata) == -22);
  CHECK(diagnostic_read(0, NULL, 1, &metadata) == -14);
  CHECK(diagnostic_read(0, bytes, sizeof(bytes), NULL) == -14);
  CHECK(diagnostic_read(0, bytes, sizeof(bytes), (void *)UINT64_MAX) == -14);
  CHECK(diagnostic_read(0, bytes, 32, (void *)(bytes + 8)) == -22);
  CHECK(diagnostic_read(UINT64_MAX, bytes, sizeof(bytes), &metadata) == -22);

  CHECK(diagnostic_read(0, NULL, 0, &metadata) == 0);
  CHECK(metadata.next_cursor == metadata.dropped);
  /* A real usercopy refusal supplies an audit record even on a quiet boot. */
  CHECK(diagnostic_read(0, NULL, 0, (void *)&read_only) == -14);
  metadata.next_cursor = UINT64_MAX;
  CHECK(diagnostic_read(0, (void *)&read_only, 1, &metadata) == -14);
  CHECK(metadata.next_cursor == UINT64_MAX);
  const int64_t copied = diagnostic_read(0, bytes, sizeof(bytes), &metadata);
  CHECK(copied > 0 && copied <= sizeof(bytes));
  CHECK(metadata.next_cursor == metadata.dropped + (uint64_t)copied);

  /* A reader's position is its own, not consumed globally by another read. */
  unsigned char replay[sizeof(bytes)];
  struct read_result repeated = {0};
  CHECK(diagnostic_read(metadata.dropped, replay, (uint64_t)copied,
                        &repeated) == copied);
  CHECK(repeated.dropped == 0 && repeated.next_cursor == metadata.next_cursor);
  CHECK(memcmp(bytes, replay, (size_t)copied) == 0);
  puts("native-diagnostic-read: authorized PASS");
  return 0;
}
