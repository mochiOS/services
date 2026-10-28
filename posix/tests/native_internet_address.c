#define _GNU_SOURCE 1
#define _POSIX_THREADS 1
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
static __thread unsigned cookie = 17;
_Static_assert(sizeof(struct in_addr) == 4, "IPv4 ABI");
_Static_assert(sizeof(struct sockaddr_in) == 16, "IPv4 socket ABI");
_Static_assert(sizeof(struct in6_addr) == 16, "IPv6 ABI");
_Static_assert(_Alignof(struct in6_addr) == 4, "IPv6 address alignment");
_Static_assert(sizeof(struct sockaddr_in6) == 28, "IPv6 socket ABI");
_Static_assert(offsetof(struct sockaddr_in6, sin6_addr) == 8,
               "IPv6 address offset");
_Static_assert(offsetof(struct sockaddr_in6, sin6_scope_id) == 24,
               "IPv6 scope offset");
static void check(int condition, unsigned line) {
  if (!condition) {
    fprintf(stderr, "internet-address: FAIL line=%u errno=%d euid=%u\n", line,
            errno, (unsigned)geteuid());
    exit(1);
  }
}
#define CHECK(x) check(!!(x), __LINE__)
static const struct address_case {
  int family;
  const char *input;
  const char *output;
} cases[] = {{AF_INET, "0.0.0.0", "0.0.0.0"},
             {AF_INET, "127.0.0.1", "127.0.0.1"},
             {AF_INET, "255.255.255.255", "255.255.255.255"},
             {AF_INET6, "::", "::"},
             {AF_INET6, "::1", "::1"},
             {AF_INET6, "2001:DB8:0:0:0:0:0:1234", "2001:db8::1234"},
             {AF_INET6, "1:0:0:2:0:0:3:4", "1::2:0:0:3:4"},
             {AF_INET6, "::FFFF:192.0.2.1", "::ffff:192.0.2.1"},
             {AF_INET6, "::192.0.2.1", "::192.0.2.1"},
             {AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",
              "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}};
static void roundtrips(void) {
  for (unsigned index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
    const struct address_case *test = &cases[index];
    unsigned char bytes[16], again[16];
    char output[INET6_ADDRSTRLEN];
    memset(bytes, 0xa5, sizeof(bytes));
    errno = EBUSY;
    CHECK(inet_pton(test->family, test->input, bytes) == 1 && errno == EBUSY);
    CHECK(inet_ntop(test->family, bytes, output, sizeof(output)) == output &&
          errno == EBUSY);
    CHECK(strcmp(output, test->output) == 0);
    CHECK(inet_pton(test->family, output, again) == 1);
    CHECK(memcmp(bytes, again, test->family == AF_INET ? 4 : 16) == 0);
    size_t length = strlen(output);
    memset(output, 0xa5, sizeof(output));
    errno = 0;
    CHECK(inet_ntop(test->family, bytes, output, (socklen_t)length) == NULL &&
          errno == ENOSPC);
    for (unsigned byte = 0; byte < sizeof(output); ++byte)
      CHECK((unsigned char)output[byte] == 0xa5);
    CHECK(inet_ntop(test->family, bytes, output, (socklen_t)length + 1) ==
          output);
  }
  puts("internet-address: PASS network order, IPv4/IPv6 presentation and "
       "buffer boundaries");
}
static void invalid(void) {
  const char *bad4[] = {"",           "127.1",      "01.2.3.4", "1.2.3.256",
                        "0x7f.0.0.1", "1.2.3.4/32", " 1.2.3.4", "1.2.3.4 "};
  const char *bad6[] = {"",
                        "1::2::3",
                        "1:2:3:4:5:6:7",
                        "1:2:3:4:5:6:7:10000",
                        "::1%2",
                        "::ffff:192.000.2.1",
                        "192.0.2.1"};
  unsigned char bytes[16];
  for (unsigned family = 0; family < 2; ++family) {
    const char **bad = family ? bad6 : bad4;
    unsigned count = family ? sizeof(bad6) / sizeof(bad6[0])
                            : sizeof(bad4) / sizeof(bad4[0]);
    for (unsigned index = 0; index < count; ++index) {
      memset(bytes, 0xa5, sizeof(bytes));
      errno = EBUSY;
      CHECK(inet_pton(family ? AF_INET6 : AF_INET, bad[index], bytes) == 0 &&
            errno == EBUSY);
      for (unsigned byte = 0; byte < sizeof(bytes); ++byte)
        CHECK(bytes[byte] == 0xa5);
    }
  }
  char long_text[257];
  memset(long_text, 'a', sizeof(long_text));
  long_text[256] = 0;
  errno = EBUSY;
  CHECK(inet_pton(AF_INET6, long_text, bytes) == 0 && errno == EBUSY);
  errno = 0;
  CHECK(inet_pton(AF_UNSPEC, (const char *)(uintptr_t)1,
                  (void *)(uintptr_t)1) == -1 &&
        errno == EAFNOSUPPORT);
  CHECK(inet_ntop(AF_UNSPEC, (const void *)(uintptr_t)1, (char *)(uintptr_t)1,
                  46) == NULL &&
        errno == EAFNOSUPPORT);
  puts("internet-address: PASS invalid syntax and unsupported family preserve "
       "output");
}
static void classification(void) {
  struct in6_addr any = IN6ADDR_ANY_INIT, loopback = IN6ADDR_LOOPBACK_INIT,
                  address;
  CHECK(memcmp(&any, &in6addr_any, 16) == 0 &&
        memcmp(&loopback, &in6addr_loopback, 16) == 0);
  CHECK(IN6_IS_ADDR_UNSPECIFIED(&any) && !IN6_IS_ADDR_LOOPBACK(&any));
  CHECK(IN6_IS_ADDR_LOOPBACK(&loopback) && !IN6_IS_ADDR_UNSPECIFIED(&loopback));
  CHECK(!IN6_IS_ADDR_V4COMPAT(&any) && !IN6_IS_ADDR_V4COMPAT(&loopback));
  CHECK(inet_pton(AF_INET6, "::ffff:192.0.2.1", &address) == 1 &&
        IN6_IS_ADDR_V4MAPPED(&address));
  CHECK(inet_pton(AF_INET6, "::192.0.2.1", &address) == 1 &&
        IN6_IS_ADDR_V4COMPAT(&address));
  CHECK(inet_pton(AF_INET6, "fe80::1", &address) == 1 &&
        IN6_IS_ADDR_LINKLOCAL(&address));
  CHECK(inet_pton(AF_INET6, "fec0::1", &address) == 1 &&
        IN6_IS_ADDR_SITELOCAL(&address));
  CHECK(inet_pton(AF_INET6, "ff02::1", &address) == 1 &&
        IN6_IS_ADDR_MULTICAST(&address) && IN6_IS_ADDR_MC_LINKLOCAL(&address));
  CHECK(inet_pton(AF_INET6, "ff0e::1", &address) == 1 &&
        IN6_IS_ADDR_MC_GLOBAL(&address));
  CHECK(!IN6_IS_ADDR_MC_SITELOCAL(&address));
  puts("internet-address: PASS C address ABI, constant symbols and IPv6 "
       "classification");
}
static void guarded(void) {
  size_t page = (size_t)sysconf(_SC_PAGESIZE);
  unsigned char *mapping = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(mapping != MAP_FAILED);
  CHECK(mprotect(mapping + page, page, PROT_NONE) == 0);
  char *edge = (char *)mapping + page - 4;
  memcpy(edge, "::1", 4);
  struct in6_addr address;
  CHECK(inet_pton(AF_INET6, edge, &address) == 1 &&
        IN6_IS_ADDR_LOOPBACK(&address));
  CHECK(inet_ntop(AF_INET6, &address, edge, 4) == edge &&
        strcmp(edge, "::1") == 0);
  memcpy(mapping + page - 16, &in6addr_loopback, 16);
  char output[46];
  CHECK(inet_ntop(AF_INET6, mapping + page - 16, output, sizeof(output)) ==
            output &&
        strcmp(output, "::1") == 0);
  errno = 0;
  CHECK(inet_pton(AF_INET6, (char *)mapping + page, &address) == -1 &&
        errno == EFAULT);
  CHECK(inet_ntop(AF_INET6, mapping + page, output, sizeof(output)) == NULL &&
        errno == EFAULT);
  CHECK(inet_pton(AF_INET6, "::1", mapping + page) == -1 && errno == EFAULT);
  CHECK(inet_ntop(AF_INET6, &address, (char *)mapping + page, sizeof(output)) ==
            NULL &&
        errno == EFAULT);
  CHECK(inet_pton(AF_INET6, "::1", NULL) == -1 && errno == EFAULT);
  for (unsigned index = 0; index < 4; ++index) {
    const uintptr_t bad[] = {0, 1, UINTPTR_MAX, UINT64_C(0xffff800000000000)};
    CHECK(inet_pton(AF_INET6, (const char *)bad[index], &address) == -1 &&
          errno == EFAULT);
    CHECK(inet_ntop(AF_INET6, (const void *)bad[index], output,
                    sizeof(output)) == NULL &&
          errno == EFAULT);
  }
  CHECK(munmap(mapping, page * 2) == 0);
  puts("internet-address: PASS guarded C strings and inaccessible memory "
       "return EFAULT");
}
static void *concurrent(void *argument) {
  CHECK(cookie == 17);
  unsigned number = (unsigned)(uintptr_t)argument;
  const struct address_case *test = &cases[number];
  for (unsigned iteration = 0; iteration < 64; ++iteration) {
    char output[46];
    unsigned char bytes[16];
    int saved = number == 1 ? EBUSY : EEXIST;
    errno = saved;
    CHECK(inet_pton(test->family, test->input, bytes) == 1 && errno == saved);
    CHECK(inet_ntop(test->family, bytes, output, sizeof(output)) == output &&
          errno == saved);
    CHECK(strcmp(output, test->output) == 0);
  }
  return argument;
}
int main(int argc, char **argv) {
  CHECK(cookie == 17 && argc == 2);
  CHECK(geteuid() ==
        (unsigned)(strcmp(argv[1], "--expect-euid=501") == 0 ? 501 : 0));
  alarm(30);
  roundtrips();
  invalid();
  classification();
  guarded();
  pthread_t first, second;
  CHECK(pthread_create(&first, NULL, concurrent, (void *)(uintptr_t)1) == 0);
  CHECK(pthread_create(&second, NULL, concurrent, (void *)(uintptr_t)7) == 0);
  void *result = NULL;
  CHECK(pthread_join(first, &result) == 0 && result == (void *)(uintptr_t)1);
  CHECK(pthread_join(second, &result) == 0 && result == (void *)(uintptr_t)7);
  printf("internet-address: PASS native C API, TLS errno and parallel "
         "conversions euid=%u\n",
         (unsigned)geteuid());
  return 0;
}
