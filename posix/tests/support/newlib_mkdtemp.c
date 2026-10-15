/* Link the production newlib implementation with controlled OS hooks. The
 * SDK headers, not host libc layouts, define every reentrant argument here. */
#include <errno.h>
#include <fcntl.h>
#include <reent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x))                                                                  \
      return __LINE__;                                                         \
  } while (0)
static struct _reent local;
struct _reent *_impure_ptr = &local;
struct _reent *__getreent(void) { return &local; }
const char _ctype_[257] = {
    ['0' + 1] = 4, ['1' + 1] = 4, ['2' + 1] = 4, ['3' + 1] = 4, ['4' + 1] = 4,
    ['5' + 1] = 4, ['6' + 1] = 4, ['7' + 1] = 4, ['8' + 1] = 4, ['9' + 1] = 4,
};
static int calls, stats, opens, collisions, failure, parent_failure, bad;
static char last_path[128];

int _getpid_r(struct _reent *state) {
  (void)state;
  return 42;
}
int _stat_r(struct _reent *state, const char *path, struct stat *status) {
  ++stats;
  if (strcmp(path, "/tmp"))
    bad = 1;
  if (parent_failure) {
    _REENT_ERRNO(state) = ENOENT;
    return -1;
  }
  memset(status, 0, sizeof(*status));
  status->st_mode = S_IFDIR | 0777;
  return 0;
}
int _mkdir_r(struct _reent *state, const char *path, int mode) {
  if (mode != 0700 || (calls && !strcmp(last_path, path)))
    bad = 1;
  strcpy(last_path, path);
  ++calls;
  if (calls <= collisions) {
    _REENT_ERRNO(state) = EEXIST;
    return -1;
  }
  if (failure) {
    _REENT_ERRNO(state) = failure;
    return -1;
  }
  return 0;
}
int _open_r(struct _reent *state, const char *path, int flags, int mode) {
  (void)state;
  (void)path;
  if ((flags & (O_CREAT | O_EXCL | O_ACCMODE)) != (O_CREAT | O_EXCL | O_RDWR) ||
      mode != 0600)
    bad = 1;
  ++opens;
  return 17;
}
static void reset(void) {
  calls = stats = opens = collisions = failure = parent_failure = bad = 0;
  last_path[0] = 0;
  _REENT_ERRNO(&local) = 91;
}
int main(void) {
  reset();
  char path[] = "/tmp/directory-XXXXXX";
#ifdef __mochios__
  CHECK(mkdtemp(path) == path);
  CHECK(calls == 1 && stats == 1 && opens == 0 && !bad);
  CHECK(!strcmp(path, "/tmp/directory-000042"));
  reset();
  collisions = 3;
  char collision[] = "/tmp/collision-XXXXXX";
  CHECK(mkdtemp(collision) == collision);
  CHECK(calls == 4 && stats == 1 && opens == 0 && !bad);
  reset();
  failure = EACCES;
  char denied[] = "/tmp/denied-XXXXXX";
  CHECK(mkdtemp(denied) == NULL && _REENT_ERRNO(&local) == EACCES);
  CHECK(calls == 1 && stats == 1 && !bad);
  reset();
  parent_failure = 1;
  char absent[] = "/tmp/absent-XXXXXX";
  CHECK(mkdtemp(absent) == NULL && _REENT_ERRNO(&local) == ENOENT);
  CHECK(calls == 0 && stats == 1 && !bad);
  reset();
  char invalid[] = "/tmp/invalid-XXXXX";
  CHECK(mkdtemp(invalid) == NULL && _REENT_ERRNO(&local) == EINVAL);
  CHECK(calls == 0 && stats == 0);
  reset();
  char bare[] = "XXXXXX";
  CHECK(mkdtemp(bare) == bare && !strcmp(bare, "000042"));
  CHECK(calls == 1 && stats == 0 && !bad);
  reset();
  collisions = 3;
  char bare_collision[] = "XXXXXX";
  CHECK(mkdtemp(bare_collision) == bare_collision);
  CHECK(calls == 4 && stats == 0 && !bad);
  reset();
  failure = EACCES;
  struct _reent other = {0};
  char reentrant[] = "/tmp/reentrant-XXXXXX";
  CHECK(_mkdtemp_r(&other, reentrant) == NULL);
  CHECK(_REENT_ERRNO(&other) == EACCES && _REENT_ERRNO(&local) == 91 && !bad);
#else
  /* Other targets without HAVE_MKDIR retain their prior explicit failure. */
  CHECK(mkdtemp(path) == NULL && _REENT_ERRNO(&local) == ENOSYS);
  CHECK(calls == 0);
#endif
  reset();
  char file[] = "/tmp/file-XXXXXX";
  CHECK(mkstemp(file) == 17 && opens == 1 && calls == 0 && !bad);
  char suffix[] = "/tmp/file-XXXXXX.txt";
  CHECK(mkstemps(suffix, 4) == 17 &&
        !strcmp(suffix + strlen(suffix) - 4, ".txt"));
  CHECK(opens == 2 && calls == 0 && !bad);
  return 0;
}
