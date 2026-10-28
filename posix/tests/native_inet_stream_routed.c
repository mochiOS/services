// The external portion requires a user-mode NIC and the matching host echo
// fixture. It exercises the public C API; the kernel knows none of this setup.
#define main loopback_main
#include "native_inet_stream.c"
#undef main
#define ROUTED_TEST_PORT 28377
static void routed(void) {
  struct sockaddr_in host = {0};
  host.sin_family = AF_INET;
  host.sin_port = htons(ROUTED_TEST_PORT);
  host.sin_addr.s_addr = htonl(0x0a000202); // QEMU user-mode host endpoint.
  int fd = -1;
  for (unsigned retry = 0; retry < 500; ++retry) {
    fd = client(0);
    struct timeval timeout = {5, 0};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ==
          0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ==
          0);
    if (connect(fd, (struct sockaddr *)&host, sizeof(host)) == 0)
      break;
    int failure = errno;
    CHECK(close(fd) == 0);
    fd = -1;
    CHECK(failure == ENETUNREACH || failure == EADDRNOTAVAIL);
    delay();
  }
  CHECK(fd >= 0);
  struct sockaddr_in local;
  socklen_t size = sizeof(local);
  CHECK(getsockname(fd, (struct sockaddr *)&local, &size) == 0 &&
        size == sizeof(local));
  CHECK(local.sin_addr.s_addr != 0 &&
        ((ntohl(local.sin_addr.s_addr) >> 24) != 127));
  unsigned char sent[8192], received[8192];
  for (size_t index = 0; index < sizeof(sent); ++index)
    sent[index] = (unsigned char)(index * 31);
  memcpy(sent, "TCP7", 4);
  uint32_t uid = htonl(geteuid());
  memcpy(sent + 4, &uid, 4);
  size_t offset = 0;
  while (offset < sizeof(sent)) {
    ssize_t count = write(fd, sent + offset, sizeof(sent) - offset);
    CHECK(count > 0 && (size_t)count <= sizeof(sent) - offset);
    offset += (size_t)count;
  }
  CHECK(shutdown(fd, SHUT_WR) == 0);
  CHECK(recv(fd, received, sizeof(received), MSG_WAITALL) == sizeof(received));
  CHECK(memcmp(received, sent, sizeof(sent)) == 0 &&
        read(fd, received, 1) == 0);
  CHECK(close(fd) == 0);
  printf("inet-stream: PASS physical NIC TCP 8192-byte echo and FIN euid=%u\n",
         (unsigned)geteuid());
}
int main(int argc, char **argv) {
  int result = loopback_main(argc, argv);
  if (argc == 2)
    routed();
  return result;
}
