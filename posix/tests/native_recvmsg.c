#define SOCKET_TRANSFER_TEST_ENTRY run_transfer_regressions
#include "native_socket_transfer.c"
#include <stddef.h>
#include <fcntl.h>
#include <sys/un.h>
#include <sys/resource.h>

_Static_assert(sizeof(struct msghdr) == 56, "msghdr ABI");
_Static_assert(offsetof(struct msghdr, msg_iov) == 16, "msghdr vectors");
_Static_assert(offsetof(struct msghdr, msg_control) == 32, "msghdr control");
_Static_assert(offsetof(struct msghdr, msg_flags) == 48, "msghdr flags");
_Static_assert(sizeof(struct cmsghdr) == 16, "cmsghdr ABI");
_Static_assert(CMSG_SPACE(4) == 24 && CMSG_LEN(4) == 20, "control alignment");

static int native_sender(uint64_t service, const char *path, uint32_t *sender) {
  unsigned char request[160] = {0}, response[48] = {0};
  struct header header = {{'P', 'O', 'S', 'X'}, 1, 79, 444, 0, 16, 0, 0};
  memcpy(request, &header, 32);
  request[32] = 1;
  request[34] = 2;
  struct handles handles = {0};
  CHECK((int32_t)native(632, service, (uintptr_t)request, 48,
                       (uintptr_t)response, sizeof(response), (uintptr_t)&handles) == 32);
  CHECK(((struct header *)response)->status == 0 && handles.count == 1);
  *sender = handles.entries[0].handle;
  size_t length = strlen(path);
  header.opcode = 82;
  header.length = 8 + length;
  memcpy(request, &header, 32);
  memset(request + 32, 0, sizeof(request) - 32);
  request[32] = 1;
  uint32_t count = length;
  memcpy(request + 36, &count, 4);
  memcpy(request + 40, path, length);
  handles = (struct handles){1, 0, {{*sender, 0, (UINT64_C(1) << 63) | 256}}};
  CHECK((int32_t)native(632, service, (uintptr_t)request, 40 + length,
                       (uintptr_t)response, sizeof(response), (uintptr_t)&handles) == 40);
  CHECK(((struct header *)response)->status == 0 && !handles.count && !response[32]);
  return 0;
}

int main(void) {
  uint64_t key;
  memcpy(&key, "POSXCTRL", 8);
  uint64_t service = native(628, key, 0, 0, 0, 0, 0);
  uint32_t endpoint, sender;
  CHECK(record_endpoint(service, &endpoint) == 0);
  struct sockaddr_un address = {AF_UNIX, "/tmp/native-recvmsg.sock"};
  unlink(address.sun_path);
  int receiver = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
  CHECK(receiver >= 0 && bind(receiver, (struct sockaddr *)&address, sizeof(address)) == 0);
  CHECK(native_sender(service, address.sun_path, &sender) == 0);
  uint64_t memory = native(671, 4096, 0, 0, 0, 0, 0);
  CHECK((int64_t)memory > 0);
  CHECK(native(674, memory, (uintptr_t)"abcdefgh", 8, 0, 0, 0) == 8);
  unsigned char first[3], second[8], ancillary[CMSG_SPACE(253 * sizeof(int))];
  struct iovec vectors[3] = {{first, sizeof(first)}, {NULL, 0}, {second, sizeof(second)}};
  struct sockaddr_un source;
  struct msghdr message = {&source, sizeof(source), vectors, 3, ancillary, sizeof(ancillary), 0};
  CHECK(recvmsg(receiver, &message, MSG_DONTWAIT) == -1 && errno == EAGAIN);
  CHECK(send_refs(endpoint, sender, memory, 253) == 0);
  // The runtime's actual FD limit, not wire capacity, bounds installation.
  long expected = sysconf(_SC_OPEN_MAX) - 4;
  CHECK(expected > 0 && expected <= 253);
  CHECK(recvmsg(receiver, &message, MSG_CMSG_CLOEXEC) == 8);
  CHECK(!memcmp(first, "abc", 3) && !memcmp(second, "defgh", 5));
  CHECK(message.msg_flags == MSG_CTRUNC && message.msg_namelen == sizeof(sa_family_t));
  struct cmsghdr *header = CMSG_FIRSTHDR(&message);
  CHECK(header && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS);
  size_t descriptors = (header->cmsg_len - CMSG_LEN(0)) / sizeof(int);
  CHECK(descriptors == (size_t)expected && CMSG_NXTHDR(&message, header) == NULL);
  int *fds = (int *)CMSG_DATA(header);
  for (size_t i = 0; i < descriptors; i++) {
    CHECK(fcntl(fds[i], F_GETFD) == FD_CLOEXEC);
    CHECK(close(fds[i]) == 0);
  }
  // Exact data/control truncation, no partial FD, receiver-local CLOEXEC default.
  for (size_t capacity = 0; capacity <= 40; capacity++) {
    CHECK(send_refs(endpoint, sender, memory, 4) == 0);
    memset(ancillary, 0xa5, sizeof(ancillary));
    vectors[0].iov_len = 3;
    message = (struct msghdr){NULL, 0, vectors, 1, ancillary, capacity, 0};
    CHECK(recvmsg(receiver, &message, MSG_TRUNC) == 8);
    size_t count = capacity < CMSG_LEN(sizeof(int)) ? 0 : (capacity - CMSG_LEN(0)) / sizeof(int);
    if (count > 4) count = 4;
    CHECK(message.msg_flags == (MSG_TRUNC | (count < 4 ? MSG_CTRUNC : 0)));
    header = CMSG_FIRSTHDR(&message);
    CHECK((header != NULL) == (count != 0));
    if (header) {
      CHECK(header->cmsg_len == CMSG_LEN(count * sizeof(int)));
      fds = (int *)CMSG_DATA(header);
      for (size_t i = 0; i < count; i++) {
        CHECK(fcntl(fds[i], F_GETFD) == 0);
        CHECK(close(fds[i]) == 0);
      }
    }
    CHECK(ancillary[capacity] == 0xa5);
  }
  // Unsupported peek cannot consume the queued record or its references.
  CHECK(send_refs(endpoint, sender, memory, 1) == 0);
  message = (struct msghdr){NULL, 0, vectors, 1, ancillary, sizeof(ancillary), 0};
  CHECK(recvmsg(receiver, &message, MSG_PEEK) == -1 && errno == EOPNOTSUPP);
  CHECK(recvmsg(receiver, &message, 0) == 3 && message.msg_flags == MSG_TRUNC);
  header = CMSG_FIRSTHDR(&message);
  CHECK(header && close(*(int *)CMSG_DATA(header)) == 0);
  CHECK(close(receiver) == 0 && unlink(address.sun_path) == 0);
  CHECK(native(626, sender, 0, 0, 0, 0, 0) == 0);
  CHECK(native(626, endpoint, 0, 0, 0, 0, 0) == 0);
  CHECK(native(626, memory, 0, 0, 0, 0, 0) == 0);
  puts("recvmsg: PASS native C ABI, vectors, FD limit, control truncation, CLOEXEC and cleanup");
  fflush(stdout);
  return 0;
}
