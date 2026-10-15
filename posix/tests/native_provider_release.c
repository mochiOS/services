#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      printf("provider-release: FAIL line=%d errno=%d\n", __LINE__, errno);    \
      return 1;                                                                \
    }                                                                          \
  } while (0)

struct pr_attachment {
  uint32_t handle, reserved;
  uint64_t rights;
};
struct pr_handles {
  uint32_t count, flags;
  struct pr_attachment entries[4];
};
static int64_t pr_native(uint64_t number, uint64_t a, uint64_t b, uint64_t c,
                         uint64_t d) {
  register uint64_t fourth __asm__("r10") = d;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(a), "S"(b), "d"(c), "r"(fourth)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}

static int pr_exercise(void) {
  int64_t baseline = pr_native(680, 0, 0, 0, 0);
  CHECK(baseline > 0);
  int64_t endpoint = pr_native(629, 0, 0, 0, 0);
  CHECK(endpoint > 0);
  const uint64_t ids[] = {0, 90001, 90002};
  int64_t objects[3];
  for (unsigned index = 0; index < 3; ++index) {
    objects[index] = pr_native(637, endpoint, ids[index],
                               UINT64_C(1) | (UINT64_C(1) << 62), 0);
    CHECK(objects[index] > 0);
  }
  int64_t alias = pr_native(627, objects[0], 1, 0, 0);
  CHECK(alias > 0 && pr_native(626, alias, 0, 0, 0) == 0);
  CHECK(pr_native(691, ids[0], 0, 0, 0) == 1);
  struct pr_handles handles = {0};
  unsigned filled;
  for (filled = 0; filled < 512; ++filled) {
    int64_t sent =
        pr_native(630, endpoint, (uintptr_t) "FILL", 4, (uintptr_t)&handles);
    if (sent == -11)
      break;
    CHECK(sent == 0);
  }
  CHECK(filled > 0 && filled < 512);
  // Each following syscall retries earlier notifications against a full inbox.
  for (unsigned index = 0; index < 3; ++index) {
    CHECK(pr_native(626, objects[index], 0, 0, 0) == 0);
    CHECK(pr_native(691, ids[index], 0, 0, 0) == -9);
  }
  unsigned fillers = 0, released = 0;
  for (unsigned attempt = 0;
       attempt < 1024 && (fillers != filled || released != 7); ++attempt) {
    unsigned char bytes[64];
    memset(&handles, 0, sizeof(handles));
    int64_t received =
        pr_native(631, (uintptr_t)bytes, sizeof(bytes), (uintptr_t)&handles, 0);
    if (received == -11)
      continue;
    CHECK(received >= 0 && handles.count == 0);
    uint32_t length = (uint32_t)received;
    if (length == 4 && !memcmp(bytes, "FILL", 4)) {
      ++fillers;
    } else {
      if (length != 48 || handles.flags != 1 || memcmp(bytes, "MNUP", 4)) {
        printf("provider-release: unexpected len=%u flags=%u "
               "bytes=%02x%02x%02x%02x fillers=%u/%u released=%u\n",
               length, handles.flags, bytes[0], bytes[1], bytes[2], bytes[3],
               fillers, filled, released);
      }
      CHECK(length == 48 && handles.flags == 1 && !memcmp(bytes, "MNUP", 4));
      uint16_t opcode;
      uint64_t id;
      memcpy(&opcode, bytes + 6, 2);
      memcpy(&id, bytes + 8, 8);
      CHECK(opcode == 4);
      unsigned index;
      for (index = 0; index < 3 && ids[index] != id; ++index) {
      }
      CHECK(index < 3 && (released & (1u << index)) == 0);
      released |= 1u << index;
    }
  }
  CHECK(fillers == filled && released == 7);
  unsigned char bytes[64];
  CHECK(pr_native(631, (uintptr_t)bytes, sizeof(bytes), (uintptr_t)&handles,
                  0) == -11);
  CHECK(pr_native(626, endpoint, 0, 0, 0) == 0);
  CHECK(pr_native(680, 0, 0, 0, 0) == baseline);
  puts("provider-release: PASS final-reference-only release, full mailbox "
       "retries, "
       "zero object ID, exact-once native notifications and no Handle leaks");
  return 0;
}

static void *pr_worker(void *unused) {
  (void)unused;
  return (void *)(intptr_t)pr_exercise();
}

int main(void) {
  // The aggregate runs as the compositor and its initial thread can receive
  // unrelated service traffic. Use a fresh thread-owned inbox: do not discard
  // unknown messages or weaken validation of native release notifications.
  pthread_t worker;
  CHECK(pthread_create(&worker, NULL, pr_worker, NULL) == 0);
  void *result;
  CHECK(pthread_join(worker, &result) == 0);
  return (int)(intptr_t)result;
}
