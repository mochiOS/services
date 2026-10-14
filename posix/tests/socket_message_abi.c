#include <sys/socket.h>
#include <stddef.h>
#include <assert.h>
#include <unistd.h>

_Static_assert(sizeof(struct msghdr) == 56, "message size");
_Static_assert(offsetof(struct msghdr, msg_iov) == 16, "vector offset");
_Static_assert(offsetof(struct msghdr, msg_control) == 32, "control offset");
_Static_assert(offsetof(struct msghdr, msg_flags) == 48, "flags offset");
_Static_assert(sizeof(struct cmsghdr) == 16, "control header");
_Static_assert(CMSG_LEN(4) == 20 && CMSG_SPACE(4) == 24, "padding");
_Static_assert(MSG_CTRUNC == 8 && MSG_CMSG_CLOEXEC == 0x40000000, "flags");

int main(void) {
  union { size_t aligned; unsigned char bytes[64]; } data = {0};
  struct msghdr message = {0};
  message.msg_control = data.bytes;
  for (size_t length = 0; length < sizeof(struct cmsghdr); length++) {
    message.msg_controllen = length;
    assert(CMSG_FIRSTHDR(&message) == NULL);
  }
  message.msg_controllen = sizeof(data.bytes);
  struct cmsghdr *first = CMSG_FIRSTHDR(&message);
  assert(first == (struct cmsghdr *)data.bytes);
  first->cmsg_len = CMSG_LEN(sizeof(int));
  first->cmsg_level = SOL_SOCKET;
  first->cmsg_type = SCM_RIGHTS;
  assert(CMSG_DATA(first) == data.bytes + 16);
  struct cmsghdr *second = CMSG_NXTHDR(&message, first);
  assert(second == (struct cmsghdr *)(data.bytes + 24));
  second->cmsg_len = CMSG_LEN(sizeof(int));
  for (size_t length = 16; length < 40; length++) {
    message.msg_controllen = length;
    assert(CMSG_NXTHDR(&message, first) == NULL);
  }
  message.msg_controllen = 44; /* Final header need not have alignment padding. */
  assert(CMSG_NXTHDR(&message, first) == second);
  assert(CMSG_NXTHDR(&message, second) == NULL);
  first->cmsg_len = 15;
  assert(CMSG_NXTHDR(&message, first) == NULL);
  first->cmsg_len = SIZE_MAX;
  assert(CMSG_NXTHDR(&message, first) == NULL);
  assert(CMSG_NXTHDR(&message, NULL) == NULL);
  assert(CMSG_NXTHDR(&message, (struct cmsghdr *)(data.bytes + 60)) == NULL);
  message.msg_control = NULL;
  assert(CMSG_FIRSTHDR(&message) == NULL);
  assert(CMSG_NXTHDR(&message, first) == NULL);

  /* Exercise these actual mochiOS declarations against the host ABI, not a
     second handwritten layout. Every object is local to this test process. */
  int sockets[2], channel[2];
  assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) == 0);
  assert(pipe(channel) == 0);
  char payload = 'x';
  struct iovec vector = {&payload, 1};
  message = (struct msghdr){NULL, 0, &vector, 1, data.bytes, CMSG_SPACE(sizeof(int)), 0};
  first = CMSG_FIRSTHDR(&message);
  first->cmsg_len = CMSG_LEN(sizeof(int));
  first->cmsg_level = SOL_SOCKET;
  first->cmsg_type = SCM_RIGHTS;
  *(int *)CMSG_DATA(first) = channel[0];
  assert(sendmsg(sockets[0], &message, 0) == 1);
  assert(close(channel[0]) == 0);
  payload = 0;
  message.msg_controllen = sizeof(data.bytes);
  assert(recvmsg(sockets[1], &message, MSG_CMSG_CLOEXEC) == 1 && payload == 'x');
  first = CMSG_FIRSTHDR(&message);
  assert(first && first->cmsg_len == CMSG_LEN(sizeof(int)));
  int received = *(int *)CMSG_DATA(first);
  assert(received >= 0 && write(channel[1], "q", 1) == 1);
  assert(read(received, &payload, 1) == 1 && payload == 'q');
  assert(close(received) == 0 && close(channel[1]) == 0);
  assert(close(sockets[0]) == 0 && close(sockets[1]) == 0);
  return 0;
}
