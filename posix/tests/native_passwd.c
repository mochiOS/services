#define _GNU_SOURCE 1
#include <pwd.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "passwd: FAIL line=%d errno=%d: %s\n", __LINE__, errno, #x); \
  return 1; } } while (0)
_Static_assert(sizeof(struct passwd) == 56 && offsetof(struct passwd, pw_uid) == 16
  && offsetof(struct passwd, pw_dir) == 40, "mochiOS newlib passwd ABI");

int mochi_passwd_probe(void) {
  char storage[2048], other[2048];
  struct passwd account, named, *result = NULL;
  errno = 71;
  CHECK(getpwuid_r(getuid(), &account, storage, sizeof(storage), &result) == 0);
  CHECK(result == &account && account.pw_uid == getuid() && account.pw_dir[0] == '/' && errno == 71);
  CHECK(!strcmp(account.pw_passwd, "x"));
  CHECK(getpwnam_r(account.pw_name, &named, other, sizeof(other), &result) == 0);
  CHECK(result == &named && named.pw_uid == account.pw_uid && !strcmp(named.pw_dir, account.pw_dir));
  CHECK(getpwnam_r("nonexistent-account-226", &named, other, sizeof(other), &result) == 0 && !result);
  CHECK(getpwuid_r(getuid(), &named, other, 1, &result) == ERANGE && !result);
  CHECK(getpwuid_r(getuid(), &named, (char *)1, sizeof(other), &result) == EFAULT && !result);
  CHECK(getpwnam_r((const char *)1, &named, other, sizeof(other), &result) == EFAULT && !result);
  puts("passwd: PASS real UID/name lookup caller storage range faults missing record and errno");
  return 0;
}
