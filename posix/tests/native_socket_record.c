#define main run_native_stream_regressions
#include "native_socket_pair.c"
#undef main

struct record_request {
  char magic[4];
  uint16_t version, operation;
  uint64_t offset;
  uint32_t length, flags;
  uint64_t reserved;
};
_Static_assert(sizeof(struct record_request) == 32, "record request");
static unsigned char payload[65536], copied[65536];

static int record_endpoint(uint64_t service, uint32_t *endpoint) {
  struct header request = {{'P', 'O', 'S', 'X'}, 1, 89, 321, 0, 0, 0, 0};
  struct header response = {0};
  struct handles attached = {0};
  int64_t count =
      native(632, service, (uintptr_t)&request, sizeof(request),
             (uintptr_t)&response, sizeof(response), (uintptr_t)&attached);
  if (count < 0)
    return (int)count;
  if ((uint32_t)count != 32 || response.status || response.request != 321 ||
      memcmp(response.magic, "POSX", 4) || response.opcode != 0x8000 ||
      response.length || attached.count != 1 || attached.flags ||
      attached.entries[0].rights != (UINT64_C(1) << 63 | 4))
    return -999;
  *endpoint = attached.entries[0].handle;
  return 0;
}

static int record(uint32_t endpoint, uint32_t socket, uint32_t buffer,
                  uint16_t operation, uint64_t offset, uint32_t length,
                  uint32_t flags, uint64_t socket_rights,
                  unsigned char *reply) {
  struct record_request request = {
      {'D', 'G', 'R', 'M'}, 1, operation, offset, length, flags, 0};
  struct handles attached = {
      2,
      0,
      {{socket, 0, socket_rights}, {buffer, 0, operation == 1 ? 65 : 66}}};
  int64_t count = native(632, endpoint, (uintptr_t)&request, sizeof(request),
                         (uintptr_t)reply, 144, (uintptr_t)&attached);
  if (count < 0)
    return (int)count;
  if (attached.count || attached.flags)
    return -998;
  if ((uint32_t)count == 4) {
    int32_t error;
    memcpy(&error, reply, 4);
    return error;
  }
  if ((uint32_t)count < 24 || memcmp(reply, "DGRR", 4) || reply[4] != 1 ||
      reply[6] != operation)
    return -997;
  return (uint32_t)count;
}
static uint32_t word(const unsigned char *bytes) {
  uint32_t value;
  memcpy(&value, bytes, 4);
  return value;
}
int main(void) {
  CHECK(run_native_stream_regressions() == 0);
  uint64_t key;
  memcpy(&key, "POSXCTRL", 8);
  uint64_t service = native(628, key, 0, 0, 0, 0, 0);
  uint32_t endpoint, extra;
  CHECK(record_endpoint(service, &endpoint) == 0);
  CHECK(record_endpoint(service, &extra) == 0);
  CHECK(native(626, extra, 0, 0, 0, 0, 0) == 0);
  struct handles sockets = {0};
  CHECK(create(service, 1, 2, 0, &sockets) == 0 && sockets.count == 2);
  uint32_t a = sockets.entries[0].handle, b = sockets.entries[1].handle;
  int64_t input = native(671, 69632, 0, 0, 0, 0, 0);
  int64_t output = native(671, 69632, 0, 0, 0, 0, 0);
  CHECK(input > 0 && output > 0);
  for (unsigned i = 0; i < sizeof(payload); i++)
    payload[i] = i * 71;
  CHECK(native(674, input, (uintptr_t)payload, sizeof(payload), 17, 0, 0) ==
        sizeof(payload));
  unsigned char reply[144];
  CHECK(record(endpoint, a, input, 1, 17, 65536, 0, 2, reply) == 24);
  CHECK(word(reply + 8) == 65536 && word(reply + 12) == 65536);
  CHECK(record(endpoint, a, input, 1, 17, 1, 0, 2, reply) == -11);
  for (unsigned i = 0; i < 3; i++) {
    CHECK(record(endpoint, b, output, 2, 17, 2, 1, 1, reply) == 32);
    CHECK(word(reply + 8) == 2 && word(reply + 12) == 65536 &&
          word(reply + 16) == 8);
  }
  CHECK(record(endpoint, b, output, 2, 17, 65536, 0, 1, reply) == 32);
  CHECK(native(673, output, (uintptr_t)copied, sizeof(copied), 17, 0, 0) ==
        sizeof(copied));
  CHECK(!memcmp(copied, payload, sizeof(payload)));
  CHECK(record(endpoint, b, output, 2, 17, 1, 0, 1, reply) == -11);
  puts("socket-record: PASS 64KiB atomic transfer and PEEK");
  fflush(stdout);

  // The endpoint itself grants no data authority. Direction/extent failures
  // must preserve the queued record for a later properly authorized receive.
  CHECK(record(endpoint, a, input, 1, 17, 4, 0, 1, reply) == -13);
  CHECK(record(endpoint, a, input, 1, 17, 4, 0, 2, reply) == 24);
  CHECK(record(endpoint, b, output, 2, 69631, 4, 0, 1, reply) == -22);
  CHECK((int64_t)native(634, b, (uintptr_t)copied, 4, 0, 0, 0) == -95);
  CHECK(record(endpoint, b, output, 2, 17, 2, 0, 1, reply) == 32);
  CHECK(word(reply + 8) == 2 && word(reply + 12) == 4);
  CHECK(record(endpoint, b, output, 2, 17, 1, 0, 1, reply) == -11);
  CHECK(record(endpoint, a, input, 1, 17, 0, 0, 2, reply) == 24);
  uint64_t observed;
  CHECK(wait_ready(b, 2, &observed) == 0 && (observed & 2));
  CHECK(record(endpoint, b, output, 2, 17, 0, 0, 1, reply) == 32);
  CHECK(word(reply + 8) == 0 && word(reply + 12) == 0);
  CHECK(record(endpoint, b, output, 2, 17, 0, 0, 1, reply) == -11);
  CHECK(native(626, a, 0, 0, 0, 0, 0) == 0);
  CHECK(native(626, b, 0, 0, 0, 0, 0) == 0);
  CHECK(native(626, input, 0, 0, 0, 0, 0) == 0);
  CHECK(native(626, output, 0, 0, 0, 0, 0) == 0);
  CHECK(native(626, endpoint, 0, 0, 0, 0, 0) == 0);
  puts("socket-record: PASS explicit rights, bounds, truncation, empty record, "
       "cleanup");
  return 0;
}
