#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define POSIX_SOCKET_PAIR_TEST_ENTRY run_socket_regressions
#include "native_posix_socket_pair.c"
#undef CHECK

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "socket-peek: FAIL line=%u errno=%d %s\n", __LINE__,     \
              errno, #x);                                                      \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static int pair[2];
static pthread_t receiver;
static volatile sig_atomic_t caught;
static int worker_error;
static void pause_ms(long ms) {
  struct timespec ts = {ms / 1000, ms % 1000 * 1000000};
  while (nanosleep(&ts, &ts) < 0 && errno == EINTR) {
  }
}
static uint64_t now(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts))
    return 0;
  return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}
static void handler(int sig) {
  (void)sig;
  caught++;
}
static void *staged_writer(void *unused) {
  (void)unused;
  pause_ms(150);
  if (send(pair[0], "c", 1, 0) != 1)
    worker_error = 1;
  pause_ms(150);
  if (send(pair[0], "de", 2, 0) != 2)
    worker_error = 1;
  return NULL;
}
static void *interrupt_reader(void *unused) {
  (void)unused;
  pause_ms(60);
  if (pthread_kill(receiver, SIGUSR1))
    worker_error = 1;
  return NULL;
}
static void *close_writer(void *unused) {
  (void)unused;
  pause_ms(60);
  if (shutdown(pair[0], SHUT_WR))
    worker_error = 1;
  return NULL;
}
static void *cancelled_reader(void *unused) {
  (void)unused;
  char bytes[4];
  (void)recv(pair[1], bytes, sizeof(bytes), MSG_PEEK | MSG_WAITALL);
  return (void *)1;
}

#ifndef SOCKET_PEEK_TEST_ENTRY
#define SOCKET_PEEK_TEST_ENTRY main
#endif
int SOCKET_PEEK_TEST_ENTRY(int argc, char **argv) {
  if (argc == 5 && !strcmp(argv[1], "--socket-exec"))
    return run_socket_regressions(argc, argv);
  char bytes[9000];
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
  CHECK(recv(pair[1], bytes, 1, MSG_PEEK | MSG_DONTWAIT) == -1 &&
        errno == EAGAIN);
  CHECK(send(pair[0], "ab", 2, 0) == 2);
  for (int n = 0; n < 3; n++) {
    CHECK(recv(pair[1], bytes, 8, MSG_PEEK) == 2 && !memcmp(bytes, "ab", 2));
    CHECK(recv(pair[1], bytes, 8, MSG_PEEK | MSG_WAITALL | MSG_DONTWAIT) == 2 &&
          !memcmp(bytes, "ab", 2));
  }
  CHECK(recv(pair[1], NULL, 0, MSG_PEEK | MSG_WAITALL) == 0);
  CHECK(recv(pair[1], bytes, 2, MSG_PEEK | MSG_OOB) == -1 &&
        errno == EOPNOTSUPP);
  CHECK(send(pair[0], "x", 1, MSG_PEEK) == -1 && errno == EOPNOTSUPP);
  pthread_t writer;
  clock_t cpu = clock();
  uint64_t started = now();
  CHECK(pthread_create(&writer, NULL, staged_writer, NULL) == 0);
  CHECK(recv(pair[1], bytes, 5, MSG_PEEK | MSG_WAITALL) == 5 &&
        !memcmp(bytes, "abcde", 5));
  uint64_t elapsed = now() - started;
  clock_t used = clock() - cpu;
  CHECK(pthread_join(writer, NULL) == 0 && !worker_error);
  CHECK(elapsed >= 240000000);
  CHECK(used <
        CLOCKS_PER_SEC / 10); /* a ready prefix must not cause busy-spin */
  CHECK(recv(pair[1], bytes, 5, 0) == 5 && !memcmp(bytes, "abcde", 5));
  puts("socket-peek: staged WAITALL sleeps without consuming or spinning PASS");

  /* Native IPC chunks must inspect different positions, not repeat chunk zero.
   */
  char input[9000];
  for (unsigned n = 0; n < sizeof(input); n++)
    input[n] = (char)(n * 17 + n / 4096);
  CHECK(send(pair[0], input, sizeof(input), 0) == sizeof(input));
  CHECK(recv(pair[1], bytes, sizeof(bytes), MSG_PEEK | MSG_WAITALL) ==
        sizeof(bytes));
  CHECK(!memcmp(bytes, input, sizeof(bytes)));
  CHECK(recv(pair[1], bytes, sizeof(bytes), MSG_WAITALL) == sizeof(bytes));
  CHECK(!memcmp(bytes, input, sizeof(bytes)));

  struct timeval timeout = {.tv_sec = 0, .tv_usec = 1000};
  CHECK(setsockopt(pair[1], SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) == 0);
  /* Beyond the bounded job quota: completed/time-out registrations must
   * release. */
  for (unsigned n = 0; n < 1030; n++) {
    CHECK(recv(pair[1], bytes, 1, MSG_PEEK) == -1 && errno == EAGAIN);
  }
  CHECK(send(pair[0], "q", 1, 0) == 1);
  CHECK(recv(pair[1], bytes, 2, MSG_PEEK | MSG_WAITALL) == 1 &&
        bytes[0] == 'q');
  CHECK(recv(pair[1], bytes, 1, 0) == 1 && bytes[0] == 'q');
  timeout.tv_usec = 0;
  CHECK(setsockopt(pair[1], SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) == 0);
  puts("socket-peek: timeout prefixes and notification reclamation PASS");

  receiver = pthread_self();
  struct sigaction action = {.sa_handler = handler};
  CHECK(sigemptyset(&action.sa_mask) == 0 &&
        sigaction(SIGUSR1, &action, NULL) == 0);
  for (unsigned prefix = 0; prefix < 2; prefix++) {
    if (prefix)
      CHECK(send(pair[0], "q", 1, 0) == 1);
    CHECK(pthread_create(&writer, NULL, interrupt_reader, NULL) == 0);
    ssize_t count = recv(pair[1], bytes, 2, MSG_PEEK | MSG_WAITALL);
    CHECK(prefix ? count == 1 && bytes[0] == 'q'
                 : count == -1 && errno == EINTR);
    CHECK(pthread_join(writer, NULL) == 0 && !worker_error);
    if (prefix)
      CHECK(recv(pair[1], bytes, 1, 0) == 1 && bytes[0] == 'q');
  }
  CHECK(caught == 2);
  CHECK(pthread_create(&writer, NULL, cancelled_reader, NULL) == 0);
  pause_ms(60);
  CHECK(pthread_cancel(writer) == 0);
  void *result = NULL;
  CHECK(pthread_join(writer, &result) == 0 && result == PTHREAD_CANCELED);
  CHECK(send(pair[0], "q", 1, 0) == 1);
  CHECK(pthread_create(&writer, NULL, close_writer, NULL) == 0);
  CHECK(recv(pair[1], bytes, 2, MSG_PEEK | MSG_WAITALL) == 1 &&
        bytes[0] == 'q');
  CHECK(pthread_join(writer, NULL) == 0 && !worker_error);
  CHECK(recv(pair[1], bytes, 2, 0) == 1 && bytes[0] == 'q');
  CHECK(recv(pair[1], bytes, 1, MSG_PEEK) == 0);
  CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
  puts("socket-peek: EINTR cancellation and half-close preserve queue PASS");
  CHECK(run_socket_regressions(argc, argv) == 0);
  puts("socket-peek: PASS native MSG_PEEK and WAITALL notification handles");
  return 0;
}
