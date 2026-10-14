#define SOCKET_RECORD_TEST_ENTRY run_record_regressions
#include "native_socket_record.c"
#include <time.h>

#define TRANSFER_RIGHTS ((UINT64_C(1) << 63) | 16 | 256)
struct transfer_request {
  char magic[4];
  uint16_t version, opcode;
  unsigned char data[8];
  uint64_t metadata[3];
};
static int begin_transfer(uint32_t endpoint, uint32_t socket, unsigned count,
                          uint32_t *job) {
  struct transfer_request request = {{'S', 'C', 'M', 'B'}, 1, 1, {0}, {0}};
  uint32_t length = 8;
  memcpy(request.data, &length, 4);
  memcpy(request.data + 4, &count, 2);
  struct handles handles = {1, 0, {{socket, 0, 2}}};
  int32_t status = -999;
  int64_t result = native(632, endpoint, (uintptr_t)&request, 16,
                          (uintptr_t)&status, 4, (uintptr_t)&handles);
  if (result < 0)
    return (int)result;
  if ((uint32_t)result != 4 || handles.flags)
    return -998;
  if (status)
    return status;
  if (handles.count != 1 || handles.entries[0].rights != TRANSFER_RIGHTS)
    return -997;
  *job = handles.entries[0].handle;
  return 0;
}
static int append_transfer(uint32_t endpoint, uint32_t job, uint32_t memory,
                           unsigned offset, unsigned count, uint64_t rights,
                           unsigned opcode) {
  struct transfer_request request = {{'S', 'C', 'M', 'B'}, 1, opcode, {0}, {0}};
  memcpy(request.data, &offset, 2);
  memcpy(request.data + 2, &count, 2);
  struct handles handles = {count + 1, 0, {{job, 0, 256}}};
  for (unsigned i = 0; i < count; i++) {
    // Same source Handle may be passed repeatedly; kernel creates independent
    // receiver-local references, preserving the same underlying object.
    handles.entries[i + 1].handle = memory;
    handles.entries[i + 1].rights = rights;
    request.metadata[i] = (UINT64_C(0x5046) << 48) | (UINT64_C(10) << 40) | 2;
  }
  int32_t status = -999;
  int64_t result = native(632, endpoint, (uintptr_t)&request, 16 + count * 8,
                          (uintptr_t)&status, 4, (uintptr_t)&handles);
  if (result < 0)
    return (int)result;
  if ((uint32_t)result != 4 || handles.count || handles.flags)
    return -998;
  return status;
}
static int commit_transfer(uint32_t endpoint, uint32_t job, uint32_t memory,
                           uint64_t offset, uint64_t buffer_rights) {
  struct transfer_request request = {{'S', 'C', 'M', 'B'}, 1, 3, {0}, {0}};
  memcpy(request.data, &offset, 8);
  struct handles attached = {2, 0, {{job, 0, 256}, {memory, 0, buffer_rights}}};
  int32_t status = -999;
  int64_t result = native(632, endpoint, (uintptr_t)&request, 16,
                          (uintptr_t)&status, 4, (uintptr_t)&attached);
  if (result < 0)
    return (int)result;
  if ((uint32_t)result != 4 || attached.count || attached.flags)
    return -998;
  return status;
}
static int stage_cycle(uint64_t service, uint32_t endpoint, uint32_t memory,
                       uint32_t *a, uint32_t *b) {
  struct handles sockets = {0};
  CHECK(create(service, 1, 2, 0, &sockets) == 0 && sockets.count == 2);
  *a = sockets.entries[0].handle;
  *b = sockets.entries[1].handle;
  uint32_t job;
  CHECK(begin_transfer(endpoint, *a, 253, &job) == 0);
  CHECK(commit_transfer(endpoint, job, memory, 0, 65) == -22);
  for (unsigned offset = 0; offset < 253;) {
    unsigned count = 253 - offset;
    if (count > 3)
      count = 3;
    // Deliberately leave the helper's RAM metadata hint unchanged: native GC
    // must identify these socket references instead of trusting that hint.
    CHECK(append_transfer(endpoint, job, *b, offset, count,
                          (UINT64_C(1) << 63) | 1, 2) == (int)(offset + count));
    offset += count;
  }
  CHECK(commit_transfer(endpoint, job, memory, 0, 66) == -13);
  CHECK(commit_transfer(endpoint, job, memory, 4095, 65) == -22);
  CHECK(commit_transfer(endpoint, job, memory, UINT64_MAX, 65) == -22);
  CHECK(commit_transfer(endpoint, job, memory, 0, 65) == 8);
  CHECK(commit_transfer(endpoint, job, memory, 0, 65) == -114);
  CHECK(native(626, job, 0, 0, 0, 0, 0) == 0);
  return 0;
}
static int idle_gc(uint64_t service, uint32_t endpoint, uint32_t memory) {
  CHECK(native(674, memory, (uintptr_t) "anc-data", 8, 0, 0, 0) == 8);
  uint32_t a, b;
  CHECK(stage_cycle(service, endpoint, memory, &a, &b) == 0);
  struct timespec delay = {2, 0};
  CHECK(nanosleep(&delay, NULL) == 0);
  unsigned char reply[144], bytes[8];
  CHECK(record(endpoint, b, memory, 2, 0, 8, 0, 1, reply) == 32);
  CHECK(native(673, memory, (uintptr_t)bytes, 8, 0, 0, 0) == 8 &&
        !memcmp(bytes, "anc-data", 8));
  CHECK(record(endpoint, b, memory, 2, 0, 8, 0, 1, reply) == -11);
  CHECK(native(626, a, 0, 0, 0, 0, 0) == 0 &&
        native(626, b, 0, 0, 0, 0, 0) == 0);
  puts("socket-transfer: PASS atomic native commit, buffer validation, no "
       "duplicate, external root retained during idle GC");
  fflush(stdout);
  // Keep four real self-cycles rooted, filling 1012 of 1024 reference slots.
  // They must NOT be collected simply because queue-only refs dominate.
  uint32_t roots[4][2];
  for (unsigned i = 0; i < 4; i++)
    CHECK(stage_cycle(service, endpoint, memory, &roots[i][0], &roots[i][1]) ==
          0);
  struct handles sockets = {0};
  CHECK(create(service, 1, 2, 0, &sockets) == 0 && sockets.count == 2);
  uint32_t source = sockets.entries[0].handle,
           other = sockets.entries[1].handle, job;
  CHECK(begin_transfer(endpoint, source, 253, &job) == -105);
  for (unsigned i = 0; i < 4; i++)
    for (unsigned j = 0; j < 2; j++)
      CHECK(native(626, roots[i][j], 0, 0, 0, 0, 0) == 0);
  // No worker RPC while idle: only its native endpoint deadline can cause GC.
  delay.tv_sec = 2;
  CHECK(nanosleep(&delay, NULL) == 0);
  CHECK(begin_transfer(endpoint, source, 253, &job) == 0);
  CHECK(native(626, job, 0, 0, 0, 0, 0) == 0);
  CHECK(native(626, source, 0, 0, 0, 0, 0) == 0 &&
        native(626, other, 0, 0, 0, 0, 0) == 0);
  puts("socket-transfer: PASS idle native self-cycle collection and quota "
       "reclamation after final external close");
  fflush(stdout);
  return 0;
}
static int mutual_gc(uint64_t service, uint32_t endpoint, uint32_t memory) {
  uint32_t sockets[2][2], job;
  for (unsigned pair = 0; pair < 2; pair++) {
    struct handles handles = {0};
    CHECK(create(service, 1, 2, 0, &handles) == 0 && handles.count == 2);
    for (unsigned side = 0; side < 2; side++)
      sockets[pair][side] = handles.entries[side].handle;
    for (unsigned side = 0; side < 2; side++) {
      uint32_t source = sockets[pair][side];
      CHECK(begin_transfer(endpoint, source, 253, &job) == 0);
      for (unsigned offset = 0; offset < 253;) {
        unsigned count = 253 - offset;
        if (count > 3)
          count = 3;
        // A's queue holds B and B's queue holds A. Neither final external
        // close emits a Provider release, so no IPC message can trigger GC.
        CHECK(append_transfer(endpoint, job, source, offset, count,
                              (UINT64_C(1) << 63) | 1,
                              2) == (int)(offset + count));
        offset += count;
      }
      CHECK(commit_transfer(endpoint, job, memory, 0, 65) == 8);
      CHECK(native(626, job, 0, 0, 0, 0, 0) == 0);
    }
  }
  struct handles outsider = {0};
  CHECK(create(service, 1, 2, 0, &outsider) == 0 && outsider.count == 2);
  CHECK(begin_transfer(endpoint, outsider.entries[0].handle, 253, &job) ==
        -105);
  for (unsigned pair = 0; pair < 2; pair++)
    for (unsigned side = 0; side < 2; side++)
      CHECK(native(626, sockets[pair][side], 0, 0, 0, 0, 0) == 0);
  struct timespec delay = {2, 0};
  CHECK(nanosleep(&delay, NULL) == 0);
  CHECK(begin_transfer(endpoint, outsider.entries[0].handle, 253, &job) == 0);
  CHECK(native(626, job, 0, 0, 0, 0, 0) == 0);
  for (unsigned side = 0; side < 2; side++)
    CHECK(native(626, outsider.entries[side].handle, 0, 0, 0, 0, 0) == 0);
  puts("socket-transfer: PASS idle mutual-cycle collection without any "
       "final-release notification");
  fflush(stdout);
  return 0;
}
struct receipt_info {
  uint32_t copied, length, receipt;
  uint16_t total, available;
};
static uint16_t half(const unsigned char *bytes) {
  uint16_t value;
  memcpy(&value, bytes, 2);
  return value;
}
static int receive_refs(uint32_t endpoint, uint32_t socket, uint32_t buffer,
                        uint32_t length, uint16_t maximum,
                        uint64_t socket_rights, uint64_t buffer_rights,
                        struct receipt_info *info) {
  unsigned char request[32] = {'S', 'C', 'M', 'B', 1, 0, 4, 0};
  memcpy(request + 16, &length, 4);
  memcpy(request + 20, &maximum, 2);
  unsigned char reply[160];
  struct handles attached = {
      2, 0, {{socket, 0, socket_rights}, {buffer, 0, buffer_rights}}};
  int64_t result =
      native(632, endpoint, (uintptr_t)request, 32, (uintptr_t)reply,
             sizeof(reply), (uintptr_t)&attached);
  if (result < 0)
    return (int)result;
  if ((uint32_t)result == 4)
    return (int32_t)word(reply);
  if ((uint32_t)result < 24 || memcmp(reply, "SCMR", 4) ||
      half(reply + 4) != 1 || half(reply + 6) != 4 ||
      (uint32_t)result != 24 + half(reply + 20) || half(reply + 22) ||
      attached.flags)
    return -998;
  info->copied = word(reply + 8);
  info->length = word(reply + 12);
  info->total = half(reply + 16);
  info->available = half(reply + 18);
  info->receipt = 0;
  if (attached.count != (info->available != 0))
    return -997;
  if (attached.count) {
    if (attached.entries[0].rights != TRANSFER_RIGHTS)
      return -996;
    info->receipt = attached.entries[0].handle;
  }
  return 0;
}
static int deliver_refs(uint32_t endpoint, uint32_t receipt, uint16_t offset,
                        uint16_t maximum, struct handles *files) {
  struct transfer_request request = {{'S', 'C', 'M', 'B'}, 1, 5, {0}, {0}};
  memcpy(request.data, &offset, 2);
  memcpy(request.data + 2, &maximum, 2);
  unsigned char reply[64];
  struct handles attached = {1, 0, {{receipt, 0, 256}}};
  int64_t result =
      native(632, endpoint, (uintptr_t)&request, 16, (uintptr_t)reply,
             sizeof(reply), (uintptr_t)&attached);
  if (result < 0)
    return (int)result;
  if ((uint32_t)result == 4)
    return (int32_t)word(reply);
  if ((uint32_t)result < 16 || memcmp(reply, "SCMR", 4) ||
      half(reply + 4) != 1 || half(reply + 6) != 5 ||
      half(reply + 8) != offset || attached.count == 0 ||
      attached.count > maximum || attached.count > 4 || attached.flags ||
      (uint32_t)result != 16 + 8 * attached.count ||
      half(reply + 10) != attached.count || word(reply + 12))
    return -998;
  for (unsigned i = 0; i < attached.count; i++) {
    uint64_t metadata;
    memcpy(&metadata, reply + 16 + 8 * i, 8);
    if (metadata != ((UINT64_C(0x5046) << 48) | (UINT64_C(10) << 40) | 2) ||
        attached.entries[i].rights != ((UINT64_C(1) << 63) | 1))
      return -997;
  }
  *files = attached;
  return attached.count;
}
static int send_refs(uint32_t endpoint, uint32_t source, uint32_t memory,
                     unsigned count) {
  uint32_t job;
  CHECK(begin_transfer(endpoint, source, count, &job) == 0);
  for (unsigned offset = 0; offset < count;) {
    unsigned batch = count - offset;
    if (batch > 3)
      batch = 3;
    CHECK(append_transfer(endpoint, job, memory, offset, batch,
                          (UINT64_C(1) << 63) | 1, 2) == (int)(offset + batch));
    offset += batch;
  }
  CHECK(commit_transfer(endpoint, job, memory, 0, 65) == 8);
  CHECK(native(626, job, 0, 0, 0, 0, 0) == 0);
  return 0;
}
static int native_receipts(uint64_t service, uint32_t endpoint,
                           uint32_t memory) {
  struct handles sockets = {0}, files = {0};
  CHECK(create(service, 1, 2, 0, &sockets) == 0 && sockets.count == 2);
  uint32_t a = sockets.entries[0].handle, b = sockets.entries[1].handle;
  int64_t output = native(671, 4096, 0, 0, 0, 0, 0);
  CHECK(output > 0);
  struct receipt_info info;
  CHECK(send_refs(endpoint, a, memory, 253) == 0);
  CHECK(receive_refs(endpoint, b, output, 3, 2, 2, 66, &info) == -13);
  CHECK(receive_refs(endpoint, b, output, 3, 2, 1, 65, &info) == -13);
  CHECK(receive_refs(endpoint, b, output, 3, 2, 1, 66, &info) == 0);
  CHECK(info.copied == 3 && info.length == 8 && info.total == 253 &&
        info.available == 2 && info.receipt);
  unsigned char bytes[8], reply[144];
  CHECK(native(673, output, (uintptr_t)bytes, 3, 0, 0, 0) == 3 &&
        !memcmp(bytes, "anc", 3));
  CHECK(deliver_refs(endpoint, info.receipt, 0, 4, &files) == 2);
  for (unsigned i = 0; i < files.count; i++) {
    CHECK(native(666, files.entries[i].handle, memory, 0, 0, 0, 0) == 1);
    CHECK(native(673, files.entries[i].handle, (uintptr_t)bytes, 8, 0, 0, 0) ==
              8 &&
          !memcmp(bytes, "anc-data", 8));
    CHECK((int64_t)native(674, files.entries[i].handle, (uintptr_t) "x", 1, 0,
                          0, 0) == -13);
    CHECK(native(626, files.entries[i].handle, 0, 0, 0, 0, 0) == 0);
  }
  CHECK(deliver_refs(endpoint, info.receipt, 0, 1, &files) == -22);
  CHECK(deliver_refs(endpoint, info.receipt, 2, 1, &files) == -61);
  CHECK(native(626, info.receipt, 0, 0, 0, 0, 0) == 0);
  CHECK(record(endpoint, b, output, 2, 0, 8, 0, 1, reply) == -11);
  // A full receive supports every descriptor, not just one IPC batch.
  CHECK(send_refs(endpoint, a, memory, 253) == 0);
  CHECK(receive_refs(endpoint, b, output, 8, 253, 1, 66, &info) == 0 &&
        info.available == 253);
  for (unsigned offset = 0; offset < 253;) {
    int count = deliver_refs(endpoint, info.receipt, offset, 4, &files);
    CHECK(count > 0 && count == (int)(253 - offset < 4 ? 253 - offset : 4));
    for (unsigned i = 0; i < files.count; i++) {
      CHECK(native(666, files.entries[i].handle, memory, 0, 0, 0, 0) == 1);
      CHECK(native(626, files.entries[i].handle, 0, 0, 0, 0, 0) == 0);
    }
    offset += count;
  }
  CHECK(native(626, info.receipt, 0, 0, 0, 0, 0) == 0);
  for (unsigned round = 0; round < 8; round++) {
    CHECK(send_refs(endpoint, a, memory, 253) == 0);
    CHECK(receive_refs(endpoint, b, output, 8, 253, 1, 66, &info) == 0 &&
          info.receipt);
    CHECK(deliver_refs(endpoint, info.receipt, 0, 4, &files) == 4);
    for (unsigned i = 0; i < files.count; i++)
      CHECK(native(626, files.entries[i].handle, 0, 0, 0, 0, 0) == 0);
    CHECK(native(626, info.receipt, 0, 0, 0, 0, 0) == 0);
  }
  CHECK(send_refs(endpoint, a, memory, 253) == 0);
  CHECK(receive_refs(endpoint, b, output, 8, 0, 1, 66, &info) == 0 &&
        info.total == 253 && !info.available && !info.receipt);
  CHECK(native(626, a, 0, 0, 0, 0, 0) == 0 &&
        native(626, b, 0, 0, 0, 0, 0) == 0);
  CHECK(native(626, output, 0, 0, 0, 0, 0) == 0);
  puts("socket-transfer: PASS native receive, 253 delivered Handles, rights "
       "preserved, control/data truncation, no replay, partial-abort quota "
       "reclamation");
  fflush(stdout);
  return 0;
}
#ifndef SOCKET_TRANSFER_TEST_ENTRY
#define SOCKET_TRANSFER_TEST_ENTRY main
#endif
int SOCKET_TRANSFER_TEST_ENTRY(void) {
  CHECK(run_record_regressions() == 0);
  uint64_t key;
  memcpy(&key, "POSXCTRL", 8);
  uint64_t service = native(628, key, 0, 0, 0, 0, 0);
  uint32_t endpoint, job;
  CHECK(record_endpoint(service, &endpoint) == 0);
  struct handles sockets = {0};
  CHECK(create(service, 1, 2, 0, &sockets) == 0 && sockets.count == 2);
  uint32_t a = sockets.entries[0].handle, b = sockets.entries[1].handle;
  uint64_t memory = native(671, 4096, 0, 0, 0, 0, 0);
  CHECK((int64_t)memory > 0);
  for (unsigned cycle = 0; cycle < 10; cycle++) {
    CHECK(begin_transfer(endpoint, a, 253, &job) == 0);
    CHECK(append_transfer(endpoint, job, memory, 0, 1, 1, 2) == -13);
    CHECK(append_transfer(endpoint, b, memory, 0, 1, (UINT64_C(1) << 63) | 1,
                          2) == -9);
    CHECK(append_transfer(endpoint, job, memory, 0, 1, (UINT64_C(1) << 63) | 1,
                          99) == -38);
    CHECK(append_transfer(endpoint, job, memory, 0, 3, (UINT64_C(1) << 63) | 1,
                          2) == 3);
    CHECK(append_transfer(endpoint, job, memory, 0, 1, (UINT64_C(1) << 63) | 1,
                          2) == -22);
    // A transaction cannot keep itself/another transient job alive in its data.
    CHECK(append_transfer(endpoint, job, job, 3, 1, TRANSFER_RIGHTS, 2) == -22);
    for (unsigned offset = 3; offset < 253;) {
      unsigned count = 253 - offset;
      if (count > 3)
        count = 3;
      CHECK(append_transfer(endpoint, job, memory, offset, count,
                            (UINT64_C(1) << 63) | 1,
                            2) == (int)(offset + count));
      offset += count;
    }
    CHECK(native(626, job, 0, 0, 0, 0, 0) == 0);
  }
  // Loss/cancellation after a partial batch must release reserved quota too.
  for (unsigned cycle = 0; cycle < 20; cycle++) {
    CHECK(begin_transfer(endpoint, a, 253, &job) == 0);
    CHECK(append_transfer(endpoint, job, memory, 0, 1, (UINT64_C(1) << 63) | 1,
                          2) == 1);
    CHECK(native(626, job, 0, 0, 0, 0, 0) == 0);
  }
  CHECK(idle_gc(service, endpoint, memory) == 0);
  CHECK(mutual_gc(service, endpoint, memory) == 0);
  CHECK(native_receipts(service, endpoint, memory) == 0);
  CHECK(native(626, memory, 0, 0, 0, 0, 0) == 0);
  CHECK(native(626, a, 0, 0, 0, 0, 0) == 0 &&
        native(626, b, 0, 0, 0, 0, 0) == 0);
  CHECK(native(626, endpoint, 0, 0, 0, 0, 0) == 0);
  puts("socket-transfer: PASS native 253-handle staging, authority rejection, "
       "unknown opcode, cycle rejection, abort/release reclamation");
  fflush(stdout);
  return 0;
}
