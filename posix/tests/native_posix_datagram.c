#include <stdlib.h>
#include <sys/wait.h>
#define SOCKET_PEEK_TEST_ENTRY run_stream_regressions
#include "native_socket_peek.c"
#undef CHECK
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "posix-datagram: FAIL line=%u errno=%d %s\n", __LINE__,  \
              errno, #x);                                                      \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static unsigned char d_input[65537], d_output[65537];
static int d_pair[2], d_result, d_error, d_done;
static uint64_t d_cpu;
static void *d_send(void *unused) {
  (void)unused;
  clock_t before = clock();
  d_result = send(d_pair[0], d_input, 30000, 0);
  d_error = errno;
  d_cpu = clock() - before;
  __atomic_store_n(&d_done, 1, __ATOMIC_RELEASE);
  return NULL;
}
static void *d_receive(void *unused) {
  (void)unused;
  d_result = recv(d_pair[1], d_output, 10, MSG_WAITALL);
  d_error = errno;
  __atomic_store_n(&d_done, 1, __ATOMIC_RELEASE);
  return NULL;
}

static int named_datagrams(void) {
  const char *paths[] = {"/tmp/posix-dgram-first", "/tmp/posix-dgram-second",
                         "/tmp/posix-dgram-client"};
  struct sockaddr_un addresses[3];
  socklen_t lengths[3];
  int sockets[3];
  for (unsigned i = 0; i < 3; i++) {
    memset(&addresses[i], 0, sizeof(addresses[i]));
    addresses[i].sun_family = AF_UNIX;
    strcpy(addresses[i].sun_path, paths[i]);
    lengths[i] = offsetof(struct sockaddr_un, sun_path) + strlen(paths[i]) + 1;
    unlink(paths[i]);
    sockets[i] = socket(AF_UNIX, SOCK_DGRAM, 0);
    CHECK(sockets[i] >= 0 &&
          bind(sockets[i], (struct sockaddr *)&addresses[i], lengths[i]) == 0);
  }
  int first = sockets[0], second = sockets[1], client = sockets[2];
  CHECK(connect(client, (struct sockaddr *)&addresses[0], lengths[0]) == 0);
  CHECK(connect(first, (struct sockaddr *)&addresses[2], lengths[2]) == 0);
  CHECK(send(client, "one", 3, 0) == 3);
  struct sockaddr_un source;
  socklen_t source_length = sizeof(source);
  CHECK(recvfrom(first, d_output, sizeof(d_output), 0,
                 (struct sockaddr *)&source, &source_length) == 3);
  CHECK(!memcmp(d_output, "one", 3) && !strcmp(source.sun_path, paths[2]));
  CHECK(send(first, "old", 3, 0) == 3);
  CHECK(connect(client, (struct sockaddr *)&addresses[1], lengths[1]) == 0);
  CHECK(send(first, "reject", 6, 0) == -1 && errno == EPERM);
  CHECK(recv(client, d_output, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
  CHECK(connect(second, (struct sockaddr *)&addresses[2], lengths[2]) == 0);
  CHECK(send(second, "new", 3, 0) == 3 && recv(client, d_output, 10, 0) == 3);
  CHECK(!memcmp(d_output, "new", 3));
  struct sockaddr_un missing = {.sun_family = AF_UNIX};
  strcpy(missing.sun_path, "/tmp/posix-dgram-missing");
  CHECK(connect(client, (struct sockaddr *)&missing,
                offsetof(struct sockaddr_un, sun_path) +
                    strlen(missing.sun_path) + 1) == -1 &&
        errno == ENOENT);
  source_length = sizeof(source);
  CHECK(getpeername(client, (struct sockaddr *)&source, &source_length) == 0 &&
        !strcmp(source.sun_path, paths[1]));
  // Unlink/rebind cannot redirect a previously authorized peer to a new socket.
  CHECK(unlink(paths[1]) == 0);
  int replacement = socket(AF_UNIX, SOCK_DGRAM, 0);
  CHECK(replacement >= 0 &&
        bind(replacement, (struct sockaddr *)&addresses[1], lengths[1]) == 0);
  CHECK(send(client, "old-peer", 8, 0) == 8 &&
        recv(second, d_output, 10, 0) == 8);
  CHECK(recv(replacement, d_output, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
  CHECK(close(second) == 0);
  CHECK(send(client, "x", 1, 0) == -1 && errno == ECONNREFUSED);
  CHECK(connect(client, (struct sockaddr *)&addresses[1], lengths[1]) == 0);
  CHECK(send(client, "replacement", 11, 0) == 11 &&
        recv(replacement, d_output, 20, 0) == 11);
  CHECK(close(first) == 0 && close(client) == 0 && close(replacement) == 0);
  for (unsigned i = 0; i < 3; i++)
    CHECK(unlink(paths[i]) == 0);
  puts("posix-datagram: PASS pathname connect, source names, peer filtering, "
       "reconnect, unlink/rebind isolation");
  fflush(stdout);
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 5 && !strcmp(argv[1], "--socket-exec"))
    return run_stream_regressions(argc, argv);
  if (argc == 3 && !strcmp(argv[1], "--datagram-exec")) {
    int fd = atoi(argv[2]);
    CHECK(recv(fd, d_output, 10, MSG_WAITALL) == 3 &&
          !memcmp(d_output, "exe", 3));
    CHECK(close(fd) == 0);
    return 0;
  }
  for (unsigned i = 0; i < sizeof(d_input); i++)
    d_input[i] = i * 71;
  CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, d_pair) == 0);
  int type = 0;
  socklen_t type_length = sizeof(type);
  CHECK(getsockopt(d_pair[0], SOL_SOCKET, SO_TYPE, &type, &type_length) == 0 &&
        type == SOCK_DGRAM);
  CHECK(recv(d_pair[1], d_output, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
  CHECK(send(d_pair[0], d_input, 65537, 0) == -1 && errno == EMSGSIZE);
  CHECK(send(d_pair[0], d_input, 65536, 0) == 65536);
  CHECK(recv(d_pair[1], d_output, 2, MSG_PEEK | MSG_TRUNC | MSG_WAITALL) ==
        65536);
  CHECK(!memcmp(d_output, d_input, 2));
  unsigned char address[110];
  memset(address, 0x55, sizeof(address));
  socklen_t length = 1;
  CHECK(recvfrom(d_pair[1], d_output, 65536, 0, (struct sockaddr *)address,
                 &length) == 65536);
  CHECK(length == 2 && address[0] == AF_UNIX && address[1] == 0x55);
  CHECK(!memcmp(d_output, d_input, 65536));
  CHECK(sendto(d_pair[0], "abc", 3, 0, NULL, 0) == 3);
  CHECK(recvfrom(d_pair[1], d_output, 1, 0, NULL, (void *)(uintptr_t)1) == 1 &&
        d_output[0] == 'a');
  CHECK(recv(d_pair[1], d_output, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
  CHECK(send(d_pair[0], NULL, 0, 0) == 0);
  struct pollfd item = {d_pair[1], POLLIN, 0};
  CHECK(poll(&item, 1, 0) == 1 && (item.revents & POLLIN));
  CHECK(recv(d_pair[1], NULL, 0, 0) == 0);
  CHECK(recv(d_pair[1], d_output, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
  CHECK(write(d_pair[0], "xy", 2) == 2 && read(d_pair[1], d_output, 10) == 2);
  CHECK(!memcmp(d_output, "xy", 2));
  int alias = dup(d_pair[0]);
  CHECK(alias >= 0);
  CHECK(fcntl(alias, F_SETFL, O_NONBLOCK) == 0);
  CHECK((fcntl(d_pair[0], F_GETFL, 0) & O_NONBLOCK) != 0);
  CHECK(send(alias, "z", 1, 0) == 1 && recv(d_pair[1], d_output, 10, 0) == 1);
  CHECK(fcntl(alias, F_SETFL, 0) == 0 && close(alias) == 0);
  puts("posix-datagram: PASS C record boundaries, 64KiB, source, PEEK/TRUNC, "
       "empty, read/write, dup");
  fflush(stdout);

  CHECK(send(d_pair[0], d_input, 40000, 0) == 40000);
  d_done = 0;
  pthread_t worker;
  CHECK(pthread_create(&worker, NULL, d_send, NULL) == 0);
  pause_ms(150);
  CHECK(!__atomic_load_n(&d_done, __ATOMIC_ACQUIRE));
  CHECK(recv(d_pair[1], d_output, sizeof(d_output), 0) == 40000);
  CHECK(pthread_join(worker, NULL) == 0 && d_result == 30000);
  CHECK(d_cpu < (uint64_t)CLOCKS_PER_SEC / 10);
  CHECK(recv(d_pair[1], d_output, sizeof(d_output), 0) == 30000);
  struct timeval timeout = {0, 10000};
  CHECK(setsockopt(d_pair[0], SOL_SOCKET, SO_SNDTIMEO, &timeout,
                   sizeof(timeout)) == 0);
  CHECK(send(d_pair[0], d_input, 40000, 0) == 40000);
  for (unsigned i = 0; i < 20; i++)
    CHECK(send(d_pair[0], d_input, 30000, 0) == -1 && errno == EAGAIN);
  timeout.tv_usec = 0;
  CHECK(setsockopt(d_pair[0], SOL_SOCKET, SO_SNDTIMEO, &timeout,
                   sizeof(timeout)) == 0);
  d_done = 0;
  CHECK(pthread_create(&worker, NULL, d_send, NULL) == 0);
  pause_ms(50);
  CHECK(pthread_cancel(worker) == 0);
  void *result;
  CHECK(pthread_join(worker, &result) == 0 && result == PTHREAD_CANCELED);
  CHECK(recv(d_pair[1], d_output, sizeof(d_output), 0) == 40000);
  CHECK(recv(d_pair[1], d_output, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
  d_done = 0;
  CHECK(pthread_create(&worker, NULL, d_receive, NULL) == 0);
  pause_ms(50);
  CHECK(send(d_pair[0], "abc", 3, 0) == 3);
  CHECK(pthread_join(worker, NULL) == 0 && d_result == 3);
  puts("posix-datagram: PASS atomic blocking send sleeps, timeout, "
       "cancellation, WAITALL single record");
  fflush(stdout);

  CHECK(send(d_pair[0], "exe", 3, 0) == 3);
  char fd_text[16];
  snprintf(fd_text, sizeof(fd_text), "%d", d_pair[1]);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    char *arguments[] = {"datagram-test", "--datagram-exec", fd_text, NULL};
    char *environment[] = {NULL};
    execve("/system/services/compositor.service", arguments, environment);
    _exit(90);
  }
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  CHECK(recv(d_pair[1], d_output, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
  CHECK(shutdown(d_pair[1], SHUT_RD) == 0);
  CHECK(recv(d_pair[1], d_output, 1, 0) == 0);
  CHECK(close(d_pair[0]) == 0 && close(d_pair[1]) == 0);
  puts("posix-datagram: PASS fork/exec subtype inheritance and read shutdown");
  fflush(stdout);
  CHECK(named_datagrams() == 0);
  return run_stream_regressions(argc, argv);
}
