#define _GNU_SOURCE 1
#include <grp.h>
#include <pwd.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "groups: FAIL line=%d errno=%d: %s\n", __LINE__, errno, #x); \
  return 1; } } while (0)
_Static_assert(sizeof(struct group) == 32 && sizeof(gid_t) == 2
  && offsetof(struct group, gr_gid) == 16 && offsetof(struct group, gr_mem) == 24,
  "mochiOS newlib group ABI");

int mochi_groups_probe(void) {
  char storage[4096], other[4096];
  struct group group, named, *result = NULL;
  errno = 71;
  int status = getgrgid_r(getgid(), &group, storage, sizeof(storage), &result);
  if (status != 0) fprintf(stderr, "groups: lookup status=%d gid=%u\n", status, (unsigned)getgid());
  CHECK(status == 0);
  CHECK(result == &group && group.gr_gid == getgid() && group.gr_mem && errno == 71);
  CHECK(!strcmp(group.gr_passwd, "x"));
  CHECK(getgrnam_r(group.gr_name, &named, other, sizeof(other), &result) == 0);
  CHECK(result == &named && named.gr_gid == group.gr_gid && !strcmp(named.gr_name, group.gr_name));
  CHECK(getgrnam_r("nonexistent-group-341", &named, other, sizeof(other), &result) == 0 && !result);
  CHECK(getgrgid_r(getgid(), &named, other, 1, &result) == ERANGE && !result);
  CHECK(getgrgid_r(getgid(), &named, (char *)1, sizeof(other), &result) == EFAULT && !result);
  CHECK(getgrnam_r((const char *)1, &named, other, sizeof(other), &result) == EFAULT && !result);
  struct passwd *account = getpwuid(getuid());
  CHECK(account && account->pw_name);
  char name[128];
  CHECK(strlen(account->pw_name) < sizeof(name));
  strcpy(name, account->pw_name);
  struct group *cached = getgrgid(getgid());
  CHECK(cached && cached->gr_gid == group.gr_gid && !strcmp(cached->gr_name, group.gr_name));
  CHECK(getgrnam(cached->gr_name) == cached);
  CHECK(!strcmp(account->pw_name, name));
  puts("groups: PASS real GID/name lookup private storage member table missing records faults and errno");
  return 0;
}
