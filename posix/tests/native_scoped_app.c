#define _GNU_SOURCE 1
#define _POSIX_THREADS 1
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef APP_DYNAMIC
#define main tls_fixture_main
#include "native_tls_dso.c"
#undef main
#else
#include <stdio.h>
#include <string.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "scoped-app: failed %s\n", #x);                          \
      return 1;                                                                \
    }                                                                          \
  } while (0)
#endif

int main(int argc, char **argv) {
  const char *parent = getenv("EXPECT_PARENT");
  CHECK(parent && getppid() == atoi(parent));
  CHECK(getenv("KEEP") && strcmp(getenv("KEEP"), "1") == 0);
  CHECK(getuid() == 0 && getgid() == 0 && getegid() == 20);
  gid_t groups[2];
  CHECK(getgroups(2, groups) == 2 && groups[0] == 20 && groups[1] == 42);
  char cwd[128];
  CHECK(getcwd(cwd, sizeof(cwd)) &&
        strcmp(cwd, "/tmp/scoped-application-263") == 0);
  CHECK(umask(0) == 0027);
  struct rlimit limit;
  CHECK(getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur == 64);
#ifdef APP_DYNAMIC
  return tls_fixture_main(argc, argv);
#else
  (void)argv;
  CHECK(argc == 2 && geteuid() == 501);
  return 42;
#endif
}
