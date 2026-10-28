#include <arpa/inet.h>
#include <stddef.h>
constexpr in6_addr any = IN6ADDR_ANY_INIT;
constexpr in6_addr loopback = IN6ADDR_LOOPBACK_INIT;
static_assert(sizeof(in_addr) == 4 && sizeof(sockaddr_in) == 16);
static_assert(sizeof(in6_addr) == 16 && alignof(in6_addr) == 4);
static_assert(sizeof(sockaddr_in6) == 28 && offsetof(sockaddr_in6, sin6_scope_id) == 24);
static_assert(any.s6_addr[15] == 0 && loopback.s6_addr[15] == 1);
int (*parse)(int, const char *, void *) = &inet_pton;
const char *(*format)(int, const void *, char *, socklen_t) = &inet_ntop;
const in6_addr *exported_any = &in6addr_any;
const in6_addr *exported_loopback = &in6addr_loopback;
