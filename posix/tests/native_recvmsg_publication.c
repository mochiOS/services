/* Combine real blocked-I/O regressions with faults after rights delivery.
 * No runtime hooks: bad output pages exercise the actual synchronous upcall. */
#define main run_blocked_io_regressions
#include "native_io_resource_escape.c"
#undef main
#include <sys/mman.h>

static sigjmp_buf publication_escape;
static volatile sig_atomic_t publication_fault;
static unsigned publication_kind, publication_case;
struct delayed_rights {
  unsigned receiver;
  int socket;
  const struct msghdr *message;
  const char *prefix;
};

static void *send_after_prefix(void *argument) {
  struct delayed_rights *call = argument;
  for (unsigned attempt = 0; attempt < 5000; ++attempt) {
    struct thread_status status = {0};
    if (native(658, call->receiver, (uintptr_t)&status, 0))
      return (void *)1;
    if ((status.state == 3 || status.state == 4) &&
        !memcmp(call->prefix, "abc", 3))
      return sendmsg(call->socket, call->message, 0) == 4 ? NULL : (void *)2;
    struct timespec delay = {0, 1000000};
    if (nanosleep(&delay, NULL))
      return (void *)3;
  }
  return (void *)4;
}
#undef CHECK
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr,                                                          \
              "recvmsg-publication: FAIL kind=%u case=%u line=%u "             \
              "errno=%d: %s\n",                                                \
              publication_kind, publication_case, __LINE__, errno, #x);        \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static void publication_handler(int signal) {
  if (signal != SIGSEGV)
    _exit(91);
  publication_fault = 1;
  siglongjmp(publication_escape, 37);
}

int main(void) {
  if (run_blocked_io_regressions())
    return 1;
  struct sigaction action = {0}, previous;
  action.sa_handler = publication_handler;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, &previous) == 0);
  for (publication_kind = 0; publication_kind < 2; ++publication_kind) {
    for (publication_case = 0; publication_case < 6; ++publication_case) {
      if (publication_kind && publication_case == 5)
        continue;
      int64_t start = native(680, 0, 0, 0);
      int pair[2], files[2];
      CHECK(start > 0 && pipe(files) == 0);
      CHECK(socketpair(AF_UNIX, publication_kind ? SOCK_DGRAM : SOCK_STREAM, 0,
                       pair) == 0);
      unsigned char *page = mmap(NULL, 12288, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      CHECK(page != MAP_FAILED);
      struct msghdr *output = (struct msghdr *)page;
      unsigned char *control_bytes = page + 4096;
      char *payload = (char *)page + 8192;
      struct iovec input_vectors[2] = {{"abc", 3}, {"DEFG", 4}};
      union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(sizeof(int))];
      } control_input = {0};
      struct msghdr input = {.msg_iov = input_vectors,
                             .msg_iovlen = 2,
                             .msg_control = control_input.bytes,
                             .msg_controllen = sizeof(control_input.bytes)};
      struct cmsghdr *header = CMSG_FIRSTHDR(&input);
      header->cmsg_level = SOL_SOCKET;
      header->cmsg_type = SCM_RIGHTS;
      header->cmsg_len = CMSG_LEN(sizeof(int));
      memcpy(CMSG_DATA(header), &files[0], sizeof(int));
      if (publication_case == 5) {
        CHECK(send(pair[0], "abc", 3, 0) == 3);
        input.msg_iov = &input_vectors[1];
        input.msg_iovlen = 1;
      }
      if (publication_case != 5)
        CHECK(sendmsg(pair[0], &input, 0) == 7);
      struct iovec vectors[2] = {{payload, 3}, {payload + 3, 4}};
      if (publication_case == 5)
        vectors[1].iov_base = (void *)(uintptr_t)1;
      *output = (struct msghdr){.msg_iov = vectors,
                                .msg_iovlen = 2,
                                .msg_control = control_bytes,
                                .msg_controllen = CMSG_SPACE(sizeof(int))};
      if (publication_case == 4) {
        output->msg_name = control_bytes;
        output->msg_namelen = 110;
      }
      if (publication_case == 1 || publication_case == 4)
        CHECK(mprotect(control_bytes, 4096, PROT_READ) == 0);
      if (publication_case == 2)
        CHECK(mprotect(output, 4096, PROT_READ) == 0);
      if (publication_case == 3)
        CHECK(mprotect(payload, 4096, PROT_NONE) == 0);
      int64_t baseline = native(680, 0, 0, 0);
      CHECK(baseline == start + 4);
      pthread_t sender;
      volatile unsigned receiver = 0;
      struct delayed_rights delayed = {0};
      if (publication_case == 5) {
        receiver = (unsigned)native(656, 0, 0, 0);
        CHECK(receiver != 0);
        delayed = (struct delayed_rights){receiver, pair[0], &input, payload};
        CHECK(pthread_create(&sender, NULL, send_after_prefix, &delayed) == 0);
      }
      publication_fault = 0;
      int jumped = sigsetjmp(publication_escape, 1);
      if (!jumped) {
        ssize_t count = recvmsg(pair[1], output,
                                MSG_CMSG_CLOEXEC |
                                    (publication_case == 5 ? MSG_WAITALL : 0));
        if (publication_case == 3) {
          CHECK(count == -1 && errno == EFAULT);
        } else if (publication_case == 5) {
          void *sent;
          CHECK(pthread_join(sender, &sent) == 0 && sent == NULL);
          CHECK(native(626, receiver, 0, 0) == 0);
          CHECK(count == 3 && !memcmp(payload, "abc", 3));
          CHECK(output->msg_controllen == 0);
        } else if (publication_case == 0) {
          CHECK(count == 7);
          CHECK(!memcmp(payload, "abcDEFG", 7));
          header = CMSG_FIRSTHDR(output);
          CHECK(header && header->cmsg_level == SOL_SOCKET &&
                header->cmsg_type == SCM_RIGHTS &&
                header->cmsg_len == CMSG_LEN(sizeof(int)));
          int received;
          memcpy(&received, CMSG_DATA(header), sizeof(received));
          CHECK(received >= 0 && (fcntl(received, F_GETFD) & FD_CLOEXEC));
          CHECK(write(files[1], "q", 1) == 1);
          char byte = 0;
          CHECK(read(received, &byte, 1) == 1 && byte == 'q');
          CHECK(close(received) == 0);
        } else
          CHECK(0);
      } else {
        CHECK(jumped == 37 && publication_fault &&
              (publication_case == 1 || publication_case == 2 ||
               publication_case == 4));
        if (publication_case == 2) {
          /* The label was copied, but must never have become an open FD. */
          struct msghdr view = {.msg_control = control_bytes,
                                .msg_controllen = CMSG_SPACE(sizeof(int))};
          header = CMSG_FIRSTHDR(&view);
          int uncommitted;
          memcpy(&uncommitted, CMSG_DATA(header), sizeof(uncommitted));
          CHECK(fcntl(uncommitted, F_GETFD) == -1 && errno == EBADF);
        }
      }
      CHECK(publication_fault ==
            (publication_case == 1 || publication_case == 2 ||
             publication_case == 4));
      CHECK(native(680, 0, 0, 0) == baseline);
      /* Canceled reservation groups must not exhaust or retain FD slots. */
      int duplicate = dup(files[0]);
      CHECK(duplicate >= 0 && close(duplicate) == 0);
      CHECK(close(pair[0]) == 0 && close(pair[1]) == 0 &&
            close(files[0]) == 0 && close(files[1]) == 0);
      CHECK(munmap(page, 12288) == 0);
      CHECK(native(680, 0, 0, 0) == start);
      fprintf(stderr, "recvmsg-publication: kind=%u case=%u PASS\n",
              publication_kind, publication_case);
    }
  }
  CHECK(sigaction(SIGSEGV, &previous, NULL) == 0);
  puts("recvmsg-publication: PASS 11 real rights delivery/publication cases; "
       "payload, CLOEXEC, synchronous escape and no hidden FDs");
  return 0;
}
