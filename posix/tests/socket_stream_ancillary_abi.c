#include <sys/socket.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

/* Reference the real host UNIX stream behavior using the mochiOS C layout. */
int main(void) {
  for (int mode = 0; mode < 5; mode++) {
    int pair[2], channel[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0 && pipe(channel) == 0);
    union { struct cmsghdr aligned; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control = {0};
    struct iovec vector = {(void *)"bcd", 3};
    struct msghdr message = {NULL, 0, &vector, 1, control.bytes, sizeof(control), 0};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_len = CMSG_LEN(sizeof(int));
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(header), &channel[0], sizeof(int));
    assert(write(pair[0], "aa", 2) == 2);
    assert(sendmsg(pair[0], &message, 0) == 3);
    assert(write(pair[0], "ee", 2) == 2);
    char output[16] = {0};
    vector = (struct iovec){output, sizeof(output)};
    message.msg_controllen = sizeof(control);
    if (mode == 0) {
      assert(read(pair[1], output, sizeof(output)) == 5);
    } else if (mode == 3) {
      assert(recv(pair[1], output, sizeof(output), MSG_PEEK) == 5);
      assert(read(pair[1], output, sizeof(output)) == 5);
    } else {
      if (mode == 2) vector.iov_len = 3;
      if (mode == 4) {
        for (int i = 0; i < 2; i++) {
          message.msg_controllen = sizeof(control);
          assert(recvmsg(pair[1], &message, MSG_PEEK) == 5);
          header = CMSG_FIRSTHDR(&message);
          assert(header && close(*(int *)CMSG_DATA(header)) == 0);
        }
      }
      message.msg_controllen = sizeof(control);
      assert(recvmsg(pair[1], &message, 0) == (mode == 2 ? 3 : 5));
      header = CMSG_FIRSTHDR(&message);
      assert(header && close(*(int *)CMSG_DATA(header)) == 0);
    }
    assert(!memcmp(output, mode == 2 ? "aab" : "aabcd", mode == 2 ? 3 : 5));
    ssize_t count = read(pair[1], output, sizeof(output));
    assert(count == (mode == 2 ? 4 : 2));
    assert(!memcmp(output, mode == 2 ? "cdee" : "ee", count));
    assert(close(pair[0]) == 0 && close(pair[1]) == 0);
    assert(close(channel[0]) == 0 && close(channel[1]) == 0);
  }
  return 0;
}
