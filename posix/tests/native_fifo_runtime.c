/* Real newlib FD -> native FIFO Provider -> filesystem/posix IPC integration.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "fifo-runtime: FAIL line=%u errno=%d: %s\n", __LINE__,   \
              errno, #x);                                                      \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static char path[128];
static volatile sig_atomic_t broken;
static void on_pipe(int signo) {
  if (signo == SIGPIPE)
    broken++;
}
static void *blocking_writer(void *unused) {
  (void)unused;
  int fd = open(path, O_WRONLY);
  if (fd < 0)
    return (void *)(uintptr_t)1;
  if (write(fd, "hello", 5) != 5 || close(fd) != 0)
    return (void *)(uintptr_t)2;
  return NULL;
}
static void *blocking_reader(void *argument) {
  int fd = (int)(intptr_t)argument;
  char byte;
  return (void *)(intptr_t)(read(fd, &byte, 1) == 1 && byte == 'z' ? 0 : 1);
}
int main(int argc, char **argv) {
  if (argc == 4 && strcmp(argv[1], "--inherit") == 0) {
    int reader = atoi(argv[2]), writer = atoi(argv[3]);
    CHECK(fcntl(reader, F_GETFD) == -1 && errno == EBADF);
    CHECK(fcntl(writer, F_GETFD) >= 0 && write(writer, "e", 1) == 1);
    return 0;
  }
  alarm(45);
  snprintf(path, sizeof(path), "/tmp/fifo-runtime-%ld", (long)getpid());
  CHECK(mkfifo(path, 0600) == 0);
  CHECK(open(path, O_WRONLY | O_NONBLOCK) == -1 && errno == ENXIO);
  int r = open(path, O_RDONLY | O_NONBLOCK);
  CHECK(r >= 0);
  char data[1024];
  CHECK(read(r, data, 1) == 0);
  struct stat st;
  CHECK(fstat(r, &st) == 0 && S_ISFIFO(st.st_mode));
  CHECK(lseek(r, 0, SEEK_SET) == -1 && errno == ESPIPE);
  CHECK(fpathconf(r, _PC_PIPE_BUF) == 512);
  CHECK(mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, r, 0) == MAP_FAILED &&
        errno == ENODEV);
  int w = open(path, O_WRONLY | O_NONBLOCK);
  CHECK(w >= 0);
  CHECK(read(r, data, 1) == -1 && errno == EAGAIN);
  CHECK(write(w, "abc", 3) == 3 && read(r, data, 3) == 3 &&
        memcmp(data, "abc", 3) == 0);
  int duplicate = dup(r);
  CHECK(duplicate >= 0);
  CHECK(fcntl(duplicate, F_SETFL, 0) == 0 && !(fcntl(r, F_GETFL) & O_NONBLOCK));
  CHECK(fcntl(r, F_SETFL, O_NONBLOCK | O_APPEND) == 0);
  CHECK((fcntl(duplicate, F_GETFL) & (O_NONBLOCK | O_APPEND)) ==
        (O_NONBLOCK | O_APPEND));
  CHECK(close(duplicate) == 0);
  puts("fifo-runtime: PASS fd-classification-native-data-shared-flags");
  fflush(stdout);

  struct pollfd p = {.fd = r, .events = POLLIN};
  CHECK(poll(&p, 1, 0) == 0);
  CHECK(write(w, "x", 1) == 1);
  CHECK(poll(&p, 1, 1000) == 1 && (p.revents & POLLIN));
  fd_set reads;
  FD_ZERO(&reads);
  FD_SET(r, &reads);
  struct timeval timeout = {0, 0};
  CHECK(select(r + 1, &reads, NULL, NULL, &timeout) == 1 &&
        FD_ISSET(r, &reads));
  CHECK(read(r, data, 1) == 1);
  CHECK(close(w) == 0);
  p.revents = 0;
  CHECK(poll(&p, 1, 1000) == 1 && (p.revents & POLLHUP));
  CHECK(read(r, data, 1) == 0);
  CHECK(close(r) == 0);
  puts("fifo-runtime: PASS poll-select-eof-hangup");
  fflush(stdout);

  pthread_t thread;
  CHECK(pthread_create(&thread, NULL, blocking_writer, NULL) == 0);
  r = open(path, O_RDONLY);
  CHECK(r >= 0);
  CHECK(read(r, data, 5) == 5 && memcmp(data, "hello", 5) == 0);
  void *result;
  CHECK(pthread_join(thread, &result) == 0 && result == NULL);
  CHECK(close(r) == 0);
  puts("fifo-runtime: PASS blocking-open-read-notification");
  fflush(stdout);

  r = open(path, O_RDONLY | O_NONBLOCK);
  CHECK(r >= 0);
  w = open(path, O_WRONLY);
  CHECK(w >= 0);
  CHECK(fcntl(r, F_SETFL, 0) == 0);
  CHECK(pthread_create(&thread, NULL, blocking_reader, (void *)(intptr_t)r) ==
        0);
  usleep(20000);
  pid_t parked_child = fork();
  CHECK(parked_child >= 0);
  if (parked_child == 0)
    _exit(0);
  int parked_status;
  CHECK(waitpid(parked_child, &parked_status, 0) == parked_child &&
        WIFEXITED(parked_status) && WEXITSTATUS(parked_status) == 0);
  CHECK(write(w, "z", 1) == 1);
  CHECK(pthread_join(thread, &result) == 0 && result == NULL);
  CHECK(pthread_create(&thread, NULL, blocking_reader, (void *)(intptr_t)r) ==
        0);
  usleep(20000);
  CHECK(pthread_cancel(thread) == 0);
  CHECK(pthread_join(thread, &result) == 0 && result == PTHREAD_CANCELED);
  CHECK(write(w, "z", 1) == 1 && read(r, data, 1) == 1);
  puts("fifo-runtime: PASS parked-thread-fork-and-cancellation");
  fflush(stdout);
  CHECK(fcntl(r, F_SETFD, FD_CLOEXEC) == 0);
  pid_t inherited = fork();
  CHECK(inherited >= 0);
  if (inherited == 0) {
    char rarg[16], warg[16];
    snprintf(rarg, sizeof(rarg), "%d", r);
    snprintf(warg, sizeof(warg), "%d", w);
    char *args[] = {"fifo-runtime", "--inherit", rarg, warg, NULL};
    execv("/system/services/compositor.service", args);
    _exit(99);
  }
  int inherited_status;
  CHECK(waitpid(inherited, &inherited_status, 0) == inherited &&
        WIFEXITED(inherited_status) && WEXITSTATUS(inherited_status) == 0);
  CHECK(read(r, data, 1) == 1 && data[0] == 'e');
  puts("fifo-runtime: PASS exec-fifo-kind-and-cloexec");
  fflush(stdout);
  memset(data, 'a', 512);
  int flags = fcntl(w, F_GETFL);
  CHECK(fcntl(w, F_SETFL, flags | O_NONBLOCK) == 0);
  size_t filled = 0;
  ssize_t count;
  while ((count = write(w, data, 512)) > 0) {
    CHECK(count == 512);
    filled += 512;
    CHECK(filled <= 65536);
  }
  CHECK(count == -1 && errno == EAGAIN && filled == 65536);
  CHECK(read(r, data, 1) == 1);
  CHECK(write(w, data, 512) == -1 && errno == EAGAIN);
  CHECK(read(r, data, 511) == 511);
  CHECK(write(w, data, 512) == 512);
  puts("fifo-runtime: PASS blocking-read-atomic-backpressure");
  fflush(stdout);

  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0)
    _exit(fcntl(w, F_SETFL, 0) == 0 ? 0 : 1);
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  CHECK(!(fcntl(w, F_GETFL) & O_NONBLOCK));
  CHECK(close(r) == 0);
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = on_pipe;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGPIPE, &action, NULL) == 0);
  CHECK(write(w, "!", 1) == -1 && errno == EPIPE && broken == 1);
  CHECK(close(w) == 0 && unlink(path) == 0);
  puts("fifo-runtime: PASS fork-shared-description-sigpipe-cleanup");
  fflush(stdout);
  return 0;
}
