#define main address_regressions
#include "native_socket_message_address.c"
#undef main
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>

static int address_receiver;
static unsigned address_mode;
static void *bad_source;
static socklen_t *bad_source_length;
static sigjmp_buf address_jump;
static int64_t address_handles(void) {
  uint64_t number = 680;
  __asm__ volatile("syscall" : "+a"(number)
                   : "D"((uint64_t)0), "S"((uint64_t)0), "d"((uint64_t)0)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
static ssize_t invalid_address(void) {
  char byte;
  if (address_mode == 0)
    return sendto(address_receiver, "x", 1, 0, (void *)1, 110);
  return recvfrom(address_receiver, &byte, 1, MSG_PEEK, bad_source, bad_source_length);
}
static void address_fault(int signal) {
  if (signal != SIGSEGV)
    _exit(91);
  int64_t before = address_handles();
  if (invalid_address() != -1 || errno != EFAULT || address_handles() != before)
    _exit(92);
  siglongjmp(address_jump, 37);
}
static int address_errors(void) {
  int pair[2];
  char byte;
  CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0);
  CHECK(write(pair[0], "w", 1) == 1 && read(pair[1], &byte, 1) == 1);
  CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
  struct sigaction action = {0};
  action.sa_handler = address_fault;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  for (unsigned datagram = 0; datagram < 2; ++datagram) {
    for (address_mode = datagram ? 0 : 1; address_mode < 4; ++address_mode) {
      int64_t baseline = address_handles();
      CHECK(socketpair(AF_UNIX, datagram ? SOCK_DGRAM : SOCK_STREAM, 0, pair) == 0);
      address_receiver = pair[1];
      CHECK(write(pair[0], "q", 1) == 1);
      unsigned char *page = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      CHECK(page != MAP_FAILED);
      bad_source = page;
      bad_source_length = (socklen_t *)(page + 4096);
      *bad_source_length = 110;
      CHECK(mprotect(page + (address_mode == 2 ? 0 : 4096), 4096,
                     address_mode < 2 ? PROT_NONE : PROT_READ) == 0);
      int64_t before = address_handles();
      CHECK(invalid_address() == -1 && errno == EFAULT);
      CHECK(address_handles() == before);
      int jumped = sigsetjmp(address_jump, 1);
      if (!jumped) {
        *(volatile char *)(address_mode == 2 ? page : page + 4096) = 1;
        CHECK(0);
      }
      CHECK(jumped == 37 && address_handles() == before);
      CHECK(recvfrom(address_receiver, &byte, 1, 0, NULL, (void *)1) == 1 && byte == 'q');
      CHECK(recv(address_receiver, &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
      CHECK(close(pair[0]) == 0 && close(pair[1]) == 0 && munmap(page, 8192) == 0);
      CHECK(address_handles() == baseline);
    }
  }
  puts("receive-address: PASS 7 address EFAULT cases including active handlers, retained PEEK data and stable references");
  return 0;
}
int main(int argc, char **argv) {
  if (argc == 5 && !strcmp(argv[1], "--socket-exec"))
    return address_regressions(argc, argv);
  if (address_errors())
    return 1;
  return address_regressions(argc, argv);
}
