#define main terminal_resource_regressions
#include "native_terminal_resources.c"
#undef main

static unsigned helper_operation, memory_kind;
static unsigned char *helper_pages;
static void *helper_pointer;
static sigjmp_buf helper_jump;
static int invalid_helper(void) {
  errno = 0;
  switch (helper_operation) {
  case 0: return cfgetispeed(helper_pointer) == 0 ? -1 : 0;
  case 1: return cfgetospeed(helper_pointer) == 0 ? -1 : 0;
  case 2: return cfsetispeed(helper_pointer, B9600);
  case 3: return cfsetospeed(helper_pointer, B9600);
  case 4: return cfsetspeed(helper_pointer, B9600);
  default:
    cfmakeraw(helper_pointer);
    return errno == EFAULT ? -1 : 0;
  }
}
static void helper_fault(int signal) {
  if (signal != SIGSEGV || invalid_helper() != -1 || errno != EFAULT)
    _exit(95);
  siglongjmp(helper_jump, 37);
}
int main(void) {
  helper_pages = mmap(NULL, 16384, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(helper_pages != MAP_FAILED);
  struct termios initial;
  memset(&initial, 0x5a, sizeof(initial));
  initial.c_ispeed = B115200;
  initial.c_ospeed = B9600;
  memcpy(helper_pages + 12288, &initial, sizeof(initial));
  CHECK(mprotect(helper_pages + 4096, 4096, PROT_NONE) == 0);
  CHECK(mprotect(helper_pages + 12288, 4096, PROT_READ) == 0);
  errno = E2BIG;
  CHECK(cfgetispeed((struct termios *)(helper_pages + 12288)) == B115200);
  CHECK(cfgetospeed((struct termios *)(helper_pages + 12288)) == B9600 && errno == E2BIG);
  struct sigaction action = {0};
  action.sa_handler = helper_fault;
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
  int64_t baseline = native(680, 0, 0, 0);
  for (memory_kind = 0; memory_kind < 4; ++memory_kind) {
    helper_pointer = helper_pages + (memory_kind & 1 ? 12288 : 4096)
                     - (memory_kind >= 2 ? 28 : 0);
    for (helper_operation = 0; helper_operation < 6; ++helper_operation) {
      if ((memory_kind & 1) && helper_operation < 2)
        continue;
      CHECK(invalid_helper() == -1 && errno == EFAULT);
      int jumped = sigsetjmp(helper_jump, 1);
      if (!jumped) {
        *(volatile char *)(helper_pages + 4096) = 1;
        CHECK(0);
      }
      CHECK(jumped == 37);
      CHECK(native(680, 0, 0, 0) == baseline);
    }
  }
  struct termios value = initial;
  CHECK(cfsetispeed(&value, B4800) == 0 && cfgetispeed(&value) == B4800);
  CHECK(cfgetospeed(&value) == B9600);
  CHECK(cfsetospeed(&value, B19200) == 0 && cfgetospeed(&value) == B19200);
  CHECK(cfsetspeed(&value, B38400) == 0 &&
        cfgetispeed(&value) == B38400 && cfgetospeed(&value) == B38400);
  struct termios before = value;
  CHECK(cfsetspeed(&value, (speed_t)-1) == -1 && errno == EINVAL);
  CHECK(memcmp(&value, &before, sizeof(value)) == 0);
  cfmakeraw(&value);
  CHECK((value.c_iflag & (IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON)) == 0);
  CHECK((value.c_lflag & (ECHO | ECHONL | ICANON | ISIG | IEXTEN)) == 0);
  CHECK((value.c_oflag & OPOST) == 0 && (value.c_cflag & (CSIZE | PARENB)) == CS8);
  CHECK(value.c_cc[VMIN] == 1 && value.c_cc[VTIME] == 0);
  CHECK(value.c_ispeed == before.c_ispeed && value.c_ospeed == before.c_ospeed);
  CHECK(munmap(helper_pages, 16384) == 0);
  CHECK(native(680, 0, 0, 0) == baseline);
  CHECK(terminal_resource_regressions() == 0);
  puts("terminal-attributes: PASS 20 memory fault cases including active handlers, "
       "speed edits, raw mode and terminal resource regressions");
  return 0;
}
