#define _GNU_SOURCE 1
#include <grp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(condition, code) do { if (!(condition)) return code; } while (0)
int main(int argc, char **argv) {
  CHECK(argc == 2, 11);
  CHECK(getuid() == 0 && geteuid() == 501, 12);
  CHECK(getgid() == 0 && getegid() == 20, 13);
  CHECK(getppid() == (pid_t)strtoul(argv[1], NULL, 10), 14);
  char path[128];
  CHECK(getcwd(path, sizeof(path)) == path, 15);
  CHECK(strcmp(path, "/tmp/scoped-launch-261/old") == 0, 16);
  CHECK(umask(0022) == 0027, 17);
  gid_t groups[4];
  CHECK(getgroups(4, groups) == 2, 18);
  CHECK((groups[0] == 20 && groups[1] == 42) ||
        (groups[0] == 42 && groups[1] == 20), 19);
  struct rlimit limit;
  CHECK(getrlimit(RLIMIT_NOFILE, &limit) == 0, 20);
  CHECK(limit.rlim_cur == 64 && limit.rlim_max == 64, 21);
  return 0;
}
