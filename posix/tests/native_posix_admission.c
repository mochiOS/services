/* Reuse freestanding native IPC helpers. The existing assembly entry calls
 * probe below, NOT the renamed filesystem-role probe. This binary runs in
 * the test compositor role and inherits only the ordinary POSIX endpoint. */
#define probe unused_filesystem_role_probe
#include "native_filesystem_admission.c"
#undef probe
#undef CHECK
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      say("posix-admission: FAIL line " STR(__LINE__) ": " #x "\n");           \
      finish(1);                                                               \
    }                                                                          \
  } while (0)

enum { P_OPEN = 5, P_FTRUNCATE = 14, P_UNLINK = 19, P_TRUNCATE = 21 };

static int posix_status(uint16_t opcode, uint32_t flags, uint64_t length,
                        uint32_t options, struct attachments *objects) {
  unsigned char request[128] = {0};
  request[0] = 'P';
  request[1] = 'O';
  request[2] = 'S';
  request[3] = 'X';
  put(request, 4, 1, 2);
  put(request, 6, opcode, 2);
  put(request, 8, ++sequence, 8);
  put(request, 16, flags, 4);
  size_t payload = 8;
  if (opcode == P_FTRUNCATE)
    put(request, 32, length, 8);
  else {
    size_t prefix = opcode == P_UNLINK ? 12 : 16;
    payload = prefix + sizeof(path) - 1;
    if (opcode == P_OPEN) {
      put(request, 36, options, 4);
      put(request, 40, 0600, 4);
    } else if (opcode == P_TRUNCATE)
      put(request, 36, length, 8);
    put(request, 32 + prefix - 4, sizeof(path) - 1, 4);
    for (size_t i = 0; i < sizeof(path) - 1; ++i)
      request[32 + prefix + i] = path[i];
  }
  put(request, 20, payload, 4);
  int64_t result =
      native(IPC_CALL, filesystem, (uintptr_t)request, 32 + payload,
             (uintptr_t)response, 32, (uintptr_t)objects);
  CHECK(result >= 0 && (uint32_t)result == 32);
  CHECK(get(response, 0, 4) == UINT32_C(0x58534f50));
  CHECK(get(response, 4, 2) == 1 && get(response, 6, 2) == 0x8000);
  CHECK(get(response, 8, 8) == sequence && get(response, 16, 4) == 0 &&
        get(response, 20, 4) == 0);
  return (int32_t)get(response, 24, 4);
}

void probe(void) {
  say("posix-admission: starting client -> POSIX -> filesystem IPC checks\n");
  int64_t endpoint =
      native(LAUNCH_HANDLE_GET, UINT64_C(0x4c52544358534f50), 0, 0, 0, 0, 0);
  CHECK(endpoint > 0);
  filesystem = endpoint; /* Existing helper's endpoint slot; no FS authority. */
  struct attachments objects = {0};
  CHECK(posix_status(P_OPEN, ADMISSION, 0, 1 | 2 | 4 | 8, &objects) == 0);
  CHECK(objects.count == 1);
  struct object file = objects.items[0];
  objects = (struct attachments){.count = 1, .items = {file}};
  CHECK(posix_status(P_FTRUNCATE, ADMISSION, 8192, 0, &objects) == 0 &&
        objects.count == 0);
  CHECK(size(file.handle) == 8192);
  int64_t own_endpoint = native(ENDPOINT_CREATE, 0, 0, 0, 0, 0, 0);
  CHECK(own_endpoint > 0);
  for (unsigned operation = 0; operation < 3; ++operation) {
    int64_t unrelated =
        native(MEMORY_ADMISSION_CREATE, own_endpoint, 77, 0, 0, 0, 0);
    CHECK(unrelated > 0);
    uint16_t opcode = operation == 0   ? P_FTRUNCATE
                      : operation == 1 ? P_TRUNCATE
                                       : P_OPEN;
    uint32_t options = operation == 2 ? 1 | 2 | 16 : 0;
    objects = (struct attachments){0};
    if (operation == 0)
      objects.items[objects.count++] = file;
    objects.items[objects.count++] =
        (struct object){unrelated, 0, TICKET_RIGHTS};
    uint64_t before = size(file.handle);
    CHECK(posix_status(opcode, ADMISSION | ATTACHED, 5000, options, &objects) ==
          BUSY);
    CHECK(objects.count == 1 && objects.items[0].rights == TICKET_RIGHTS);
    uint32_t ticket = objects.items[0].handle;
    close_handle(unrelated);
    CHECK(native(HANDLE_RIGHTS_GET, ticket, 0, 0, 0, 0, 0) ==
          (int64_t)TICKET_RIGHTS);
    CHECK(signals(ticket) == 2 && size(file.handle) == before);
    if (operation == 0) {
      struct object read_only = file;
      read_only.rights = TRANSFER | 1;
      objects = (struct attachments){
          .count = 2, .items = {read_only, {ticket, 0, TICKET_RIGHTS}}};
      CHECK(posix_status(P_FTRUNCATE, ADMISSION | ATTACHED, 5000, 0,
                         &objects) == -13);
      CHECK(objects.count == 0 && signals(ticket) == 2 &&
            size(file.handle) == before);
    }
    objects = (struct attachments){0};
    if (operation == 0)
      objects.items[objects.count++] = file;
    objects.items[objects.count++] = (struct object){ticket, 0, TICKET_RIGHTS};
    CHECK(posix_status(opcode, ADMISSION | ATTACHED, 5000, options, &objects) ==
          0);
    if (operation == 2) {
      CHECK(objects.count == 1);
      close_handle(objects.items[0].handle);
    } else
      CHECK(objects.count == 0);
    CHECK(signals(ticket) == 8);
    CHECK(size(file.handle) == (operation == 2 ? 0 : 5000));
    close_handle(ticket);
  }
  /* Closing the client's final position must cancel it across BOTH forwarding
   * services. A leaked sender reference would keep the next update queued. */
  int64_t cancelled =
      native(MEMORY_ADMISSION_CREATE, own_endpoint, 77, 0, 0, 0, 0);
  CHECK(cancelled > 0);
  objects = (struct attachments){
      .count = 2, .items = {file, {(uint32_t)cancelled, 0, TICKET_RIGHTS}}};
  CHECK(posix_status(P_FTRUNCATE, ADMISSION | ATTACHED, 8192, 0, &objects) ==
        BUSY);
  CHECK(objects.count == 1 && signals(objects.items[0].handle) == 2);
  close_handle(cancelled);
  close_handle(objects.items[0].handle);
  objects = (struct attachments){.count = 1, .items = {file}};
  CHECK(posix_status(P_FTRUNCATE, ADMISSION, 8192, 0, &objects) == 0 &&
        objects.count == 0);
  CHECK(size(file.handle) == 8192);
  close_handle(own_endpoint);
  close_handle(file.handle);
  objects = (struct attachments){0};
  CHECK(posix_status(P_UNLINK, 0, 0, 0, &objects) == 0 && objects.count == 0);
  say("posix-admission: PASS two-hop tickets, authority rejection, "
      "cancellation and three mutation paths\n");
  finish(0);
}
