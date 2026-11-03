/* Diagnostic-only LLD --wrap hooks for the actual Vim. Never installed by the
 * normal port. Supply DEBUG_WRITE from the current mnu ABI when compiling. */
#include <errno.h>
#include <sys/select.h>
#include <unistd.h>

#ifndef DEBUG_WRITE
#error DEBUG_WRITE must be supplied from the current mnu ABI
#endif

static unsigned calls;
static void trace(const char *name, long first, long second, long third) {
  char line[128];
  unsigned used = 0;
  const char prefix[] = "vim-io: ";
  for (unsigned i = 0; i < sizeof(prefix) - 1; ++i)
    line[used++] = prefix[i];
  while (*name)
    line[used++] = *name++;
  const long values[] = {first, second, third};
  for (unsigned i = 0; i < 3; ++i) {
    line[used++] = ' ';
    unsigned long value = values[i];
    if (values[i] < 0) {
      line[used++] = '-';
      value = 0UL - value;
    }
    char digits[20];
    unsigned count = 0;
    do {
      digits[count++] = '0' + value % 10;
      value /= 10;
    } while (value);
    while (count)
      line[used++] = digits[--count];
  }
  line[used++] = '\n';
  unsigned long result = DEBUG_WRITE;
  __asm__ volatile("syscall"
                   : "+a"(result)
                   : "D"(line), "S"((unsigned long)used)
                   : "rcx", "r11", "memory");
}

extern ssize_t __real_read(int, void *, size_t);
ssize_t __wrap_read(int fd, void *output, size_t length) {
  const int enabled = fd == 0 && calls++ < 512;
  const int saved = errno;
  if (enabled)
    trace("read begin", fd, length, 0);
  errno = saved;
  const ssize_t result = __real_read(fd, output, length);
  const int error = errno;
  if (enabled)
    trace("read end", result, error, 0);
  errno = error;
  return result;
}

extern int __real_select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
int __wrap_select(int count, fd_set *readable, fd_set *writable,
                  fd_set *exceptional, struct timeval *timeout) {
  const int enabled = calls++ < 512;
  const int saved = errno;
  if (enabled)
    trace("select begin", count, timeout ? timeout->tv_sec : -1,
          timeout ? timeout->tv_usec : -1);
  errno = saved;
  const int result =
      __real_select(count, readable, writable, exceptional, timeout);
  const int error = errno;
  if (enabled)
    trace("select end", result, error, readable && FD_ISSET(0, readable));
  errno = error;
  return result;
}
