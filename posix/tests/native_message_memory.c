#define _GNU_SOURCE
#define main normal_message_abi
#include "socket_message_abi.c"
#undef main
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

static unsigned datagram, receiving, stage;
static int operation_socket;
static struct msghdr *operation_message;
static sigjmp_buf jump_target;
#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "message-memory: FAIL datagram=%u receive=%u stage=%u line=%u errno=%d: %s\n", \
          datagram, receiving, stage, __LINE__, errno, #x); return 1; } } while (0)
static int64_t handle_count(void) {
  uint64_t number = 680;
  __asm__ volatile("syscall" : "+a"(number)
                   : "D"((uint64_t)0), "S"((uint64_t)0), "d"((uint64_t)0)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
static ssize_t operation(void) {
  return receiving ? recvmsg(operation_socket, operation_message, MSG_PEEK | MSG_CMSG_CLOEXEC)
                   : sendmsg(operation_socket, operation_message, 0);
}
static void fault(int signal) {
  if (signal != SIGSEGV)
    _exit(91);
  int64_t baseline = handle_count();
  if (operation() != -1 || errno != EFAULT || handle_count() != baseline)
    _exit(92);
  siglongjmp(jump_target, 37);
}
static void rights(struct msghdr *message, void *control, int fd) {
  message->msg_control = control;
  message->msg_controllen = CMSG_SPACE(sizeof(int));
  struct cmsghdr *header = CMSG_FIRSTHDR(message);
  header->cmsg_len = CMSG_LEN(sizeof(int));
  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  memcpy(CMSG_DATA(header), &fd, sizeof(fd));
}
int main(void) {
  CHECK(normal_message_abi() == 0);
  struct sigaction action = {0};
  action.sa_handler = fault;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  unsigned cases = 0;
  for (datagram = 0; datagram < 2; ++datagram) {
    for (receiving = 0; receiving < 2; ++receiving) {
      for (stage = 0; stage < (receiving ? 6u : 7u); ++stage) {
        if (!datagram && ((!receiving && (stage == 4 || stage == 5)) || (receiving && stage == 3)))
          continue;
        int64_t baseline = handle_count();
        int pair[2], channel[2];
        CHECK(socketpair(AF_UNIX, datagram ? SOCK_DGRAM : SOCK_STREAM, 0, pair) == 0);
        CHECK(pipe(channel) == 0);
        unsigned char *pages = mmap(NULL, 5 * 4096, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(pages != MAP_FAILED);
        struct msghdr *message = (struct msghdr *)pages;
        struct iovec *vector = (struct iovec *)(pages + 4096);
        *vector = (struct iovec){pages + 8192, 1};
        pages[8192] = 'q';
        *message = (struct msghdr){NULL, 0, vector, 1, NULL, 0, 0};
        if (receiving || stage == 2 || stage == 5 || stage == 6)
          rights(message, pages + 12288, channel[0]);
        if (receiving || stage == 4 || stage == 5) {
          message->msg_name = pages + 16384;
          message->msg_namelen = 110;
        }
        if (receiving) {
          struct msghdr queued = {NULL, 0, vector, 1, NULL, 0, 0};
          _Alignas(struct cmsghdr) unsigned char control[CMSG_SPACE(sizeof(int))] = {0};
          rights(&queued, control, channel[0]);
          CHECK(sendmsg(pair[0], &queued, 0) == 1);
        }
        volatile unsigned protected_page = stage == 0 || (receiving && stage == 5) ? 0 :
                                  stage == 1 ? 1 :
                                  (!receiving && stage == 2) || (receiving && stage == 4) ? 3 :
                                  (!receiving && (stage == 4 || stage == 5)) || (receiving && stage == 3) ? 4 : 2;
        CHECK(mprotect(pages + protected_page * 4096, 4096,
                       receiving && stage >= 2 ? PROT_READ : PROT_NONE) == 0);
        operation_socket = pair[receiving ? 1 : 0];
        operation_message = message;
        int expected = dup(channel[0]);
        CHECK(expected >= 0 && close(expected) == 0);
        int64_t before = handle_count();
        CHECK(operation() == -1 && errno == EFAULT && handle_count() == before);
        int jumped = sigsetjmp(jump_target, 1);
        if (!jumped) {
          *(volatile char *)(pages + protected_page * 4096) = 0;
          CHECK(0);
        }
        CHECK(jumped == 37 && handle_count() == before);
        int reused = dup(channel[0]);
        CHECK(reused == expected && close(reused) == 0);
        char byte;
        if (receiving) {
          struct iovec output = {&byte, 1};
          _Alignas(struct cmsghdr) unsigned char control[CMSG_SPACE(sizeof(int))] = {0};
          struct msghdr good = {NULL, 0, &output, 1, control, sizeof(control), 0};
          CHECK(recvmsg(pair[1], &good, MSG_CMSG_CLOEXEC) == 1 && byte == 'q');
          struct cmsghdr *header = CMSG_FIRSTHDR(&good);
          CHECK(header && header->cmsg_type == SCM_RIGHTS);
          int received;
          memcpy(&received, CMSG_DATA(header), sizeof(received));
          CHECK(received == expected && close(received) == 0);
        }
        CHECK(recv(pair[1], &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
        CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
        CHECK(close(channel[0]) == 0 && close(channel[1]) == 0);
        CHECK(munmap(pages, 5 * 4096) == 0 && handle_count() == baseline);
        ++cases;
      }
    }
  }
  printf("message-memory: PASS %u EFAULT cases including active handlers, SCM_RIGHTS rollback, PEEK data and FD reuse\n", cases);
  return 0;
}
