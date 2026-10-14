#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CHECK(test) do { if (!(test)) { \
  fprintf(stderr, "sendmsg: FAIL line=%d errno=%d: %s\n", __LINE__, errno, #test); \
  return 1; } } while (0)

union ancillary {
  struct cmsghdr aligned;
  unsigned char bytes[CMSG_SPACE(253 * sizeof(int))];
};
static void message(struct msghdr *message, struct iovec *vectors, size_t count,
                    union ancillary *control, int descriptor, size_t rights) {
  memset(control, 0, sizeof(*control));
  *message = (struct msghdr){NULL, 0, vectors, count, control->bytes,
                             CMSG_SPACE(rights * sizeof(int)), 0};
  struct cmsghdr *header = CMSG_FIRSTHDR(message);
  header->cmsg_len = CMSG_LEN(rights * sizeof(int));
  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  for (size_t i = 0; i < rights; i++)
    memcpy(CMSG_DATA(header) + i * sizeof(int), &descriptor, sizeof(int));
}
static int received_fd(struct msghdr *message, size_t index) {
  int fd = -1;
  struct cmsghdr *header = CMSG_FIRSTHDR(message);
  if (header && header->cmsg_len >= CMSG_LEN((index + 1) * sizeof(int)))
    memcpy(&fd, CMSG_DATA(header) + index * sizeof(int), sizeof(fd));
  return fd;
}
static atomic_int started, finished;
struct send_state { int socket, file; ssize_t result; };
static void *blocked_send(void *opaque) {
  struct send_state *state = opaque;
  struct iovec vector = {(void *)"x", 1};
  union ancillary control;
  struct msghdr request;
  message(&request, &vector, 1, &control, state->file, 1);
  atomic_store(&started, 1);
  state->result = sendmsg(state->socket, &request, 0);
  atomic_store(&finished, 1);
  return NULL;
}

int main(void) {
  const char *path = "/tmp/native-sendmsg.txt";
  unlink(path);
  int pair[2];
  CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0);
  int file = open(path, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
  CHECK(file >= 0 && write(file, "abcdefgh", 8) == 8 && lseek(file, 0, SEEK_SET) == 0);
  struct iovec vectors[] = {{(void *)"abc", 3}, {NULL, 0}, {(void *)"def", 3}};
  union ancillary control;
  struct msghdr request;
  message(&request, vectors, 3, &control, file, 2);
  CHECK(sendmsg(pair[0], &request, 0) == 6 && close(file) == 0);
  unsigned char first[2], second[4];
  struct iovec output[] = {{first, 2}, {second, 4}};
  union ancillary incoming;
  struct msghdr response = {NULL, 0, output, 2, incoming.bytes, sizeof(incoming), 0};
  CHECK(recvmsg(pair[1], &response, 0) == 6 && response.msg_flags == 0);
  CHECK(!memcmp(first, "ab", 2) && !memcmp(second, "cdef", 4));
  int a = received_fd(&response, 0), b = received_fd(&response, 1);
  CHECK(a >= 0 && b >= 0 && a != b);
  CHECK(fcntl(a, F_GETFD) == 0 && fcntl(b, F_GETFD) == 0);
  CHECK(read(a, first, 2) == 2 && !memcmp(first, "ab", 2));
  CHECK(read(b, first, 2) == 2 && !memcmp(first, "cd", 2));
  CHECK(unlink(path) == 0); /* Delegated references keep an unlinked OFD alive. */
  message(&request, vectors, 1, &control, a, 2);
  CHECK(sendmsg(pair[0], &request, 0) == 3 && close(a) == 0 && close(b) == 0);
  response.msg_controllen = sizeof(incoming);
  CHECK(recvmsg(pair[1], &response, MSG_CMSG_CLOEXEC) == 3);
  a = received_fd(&response, 0); b = received_fd(&response, 1);
  CHECK(a >= 0 && b >= 0 && fcntl(a, F_GETFD) == FD_CLOEXEC && fcntl(b, F_GETFD) == FD_CLOEXEC);
  CHECK(read(b, first, 2) == 2 && !memcmp(first, "ef", 2));
  CHECK(close(b) == 0);
  message(&request, NULL, 0, &control, a, 1);
  CHECK(sendmsg(pair[0], &request, 0) == 0 && close(a) == 0);
  response.msg_controllen = sizeof(incoming);
  CHECK(recvmsg(pair[1], &response, 0) == 0 && response.msg_flags == 0);
  file = received_fd(&response, 0);
  CHECK(file >= 0 && read(file, first, 2) == 2 && !memcmp(first, "gh", 2));

  /* A bad late FD or control header cannot publish the valid prefix. */
  message(&request, vectors, 1, &control, file, 2);
  int invalid = 9999;
  memcpy(CMSG_DATA(CMSG_FIRSTHDR(&request)) + sizeof(int), &invalid, sizeof(invalid));
  CHECK(sendmsg(pair[0], &request, 0) == -1 && errno == EBADF);
  CHECK(recv(pair[1], first, 2, MSG_DONTWAIT) == -1 && errno == EAGAIN);
  CHECK(fcntl(file, F_GETFD) == 0);
  message(&request, vectors, 1, &control, file, 1);
  request.msg_controllen = CMSG_SPACE(sizeof(int)) + sizeof(struct cmsghdr);
  struct cmsghdr *late = (struct cmsghdr *)(control.bytes + CMSG_SPACE(sizeof(int)));
  late->cmsg_len = 1;
  CHECK(sendmsg(pair[0], &request, 0) == -1 && errno == EINVAL);
  CHECK(recv(pair[1], first, 2, MSG_DONTWAIT) == -1 && errno == EAGAIN);

  /* Full record queue: repeated failed sends must release all 253 stages. */
  static unsigned char full[65536];
  CHECK(send(pair[0], full, sizeof(full), 0) == sizeof(full));
  for (int cycle = 0; cycle < 6; cycle++) {
    message(&request, vectors, 1, &control, file, 253);
    CHECK(sendmsg(pair[0], &request, MSG_DONTWAIT) == -1 && errno == EAGAIN);
  }
  struct send_state state = {pair[0], file, -999};
  pthread_t thread;
  CHECK(pthread_create(&thread, NULL, blocked_send, &state) == 0);
  while (!atomic_load(&started)) sched_yield();
  struct timespec pause = {0, 30000000};
  CHECK(nanosleep(&pause, NULL) == 0 && !atomic_load(&finished));
  CHECK(recv(pair[1], first, 2, MSG_TRUNC) == sizeof(full));
  CHECK(pthread_join(thread, NULL) == 0 && state.result == 1);
  response.msg_controllen = sizeof(incoming);
  CHECK(recvmsg(pair[1], &response, 0) == 1 && first[0] == 'x');
  a = received_fd(&response, 0);
  CHECK(a >= 0 && close(a) == 0);
  for (int cycle = 0; cycle < 6; cycle++) {
    message(&request, vectors, 1, &control, file, 253);
    CHECK(sendmsg(pair[0], &request, 0) == 3);
    response.msg_controllen = sizeof(incoming);
    CHECK(recvmsg(pair[1], &response, 0) == 3 && response.msg_flags == MSG_CTRUNC);
    struct cmsghdr *header = CMSG_FIRSTHDR(&response);
    CHECK(header && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS);
    size_t count = (header->cmsg_len - CMSG_LEN(0)) / sizeof(int);
    CHECK(count > 0 && count < 253);
    for (size_t i = 0; i < count; i++) CHECK(close(received_fd(&response, i)) == 0);
  }
  CHECK(close(file) == 0 && close(pair[0]) == 0 && close(pair[1]) == 0);
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
  request = (struct msghdr){NULL, 0, vectors, 3, NULL, 0, 0};
  response = (struct msghdr){NULL, 0, output, 2, NULL, 0, 0};
  CHECK(sendmsg(pair[0], &request, 0) == 6 && recvmsg(pair[1], &response, 0) == 6);
  CHECK(!memcmp(first, "ab", 2) && !memcmp(second, "cdef", 4));
  CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
  puts("sendmsg: PASS native C round trip, shared/unlinked OFD, duplicate FD, CLOEXEC, empty data, malformed input, 253-right cleanup and blocking backpressure");
  fflush(stdout);
  return 0;
}
