/* A separate reader PROCESS keeps native I/O unthrottled without hiding the
 * runtime's current multithreaded-fork restriction. Spawn file actions must
 * wait fairly, update the child's live FD table, and survive actual exec. */
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "spawn-file-admission: FAIL line=%u errno=%d: %s\n", \
          __LINE__, errno, #x); return 1; } } while (0)
extern char **environ;
struct shared_state { atomic_int stop, error; atomic_uint reads; };

static int verify_child(void) {
  struct stat first, second;
  CHECK(fstat(48, &first) == 0 && first.st_size == 0);
  CHECK(fstat(51, &second) == 0 && second.st_size == 0);
  CHECK(first.st_ino == second.st_ino && first.st_dev == second.st_dev);
  CHECK(fcntl(48, F_GETFD) == 0 && fcntl(52, F_GETFD) == 0);
  CHECK(fcntl(49, F_GETFD) == -1 && errno == EBADF);
  CHECK(fcntl(50, F_GETFD) == -1 && errno == EBADF);
  CHECK(lseek(48, 17, SEEK_SET) == 17 && lseek(52, 0, SEEK_CUR) == 17);
  CHECK(lseek(51, 0, SEEK_CUR) == 0);
  char cwd[64];
  CHECK(getcwd(cwd, sizeof(cwd)) && strcmp(cwd, "/tmp") == 0);
  CHECK(close(48) == 0 && close(51) == 0 && close(52) == 0);
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--verify") == 0)
    return verify_child();
  fprintf(stderr, "spawn-file-admission: starting contended file actions\n");
  char path[] = "/tmp/spawn-file-admission-XXXXXX";
  int source = mkstemp(path);
  CHECK(source >= 0 && ftruncate(source, 8192) == 0);
  CHECK(dup2(source, 48) == 48 && fcntl(48, F_SETFD, FD_CLOEXEC) == 0);
  char initial_cwd[256];
  CHECK(getcwd(initial_cwd, sizeof(initial_cwd)) != NULL);
  struct shared_state *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  CHECK(shared != MAP_FAILED);
  atomic_store(&shared->stop, 0);
  atomic_store(&shared->error, 0);
  atomic_store(&shared->reads, 0);
  pid_t reader = fork();
  CHECK(reader >= 0);
  if (!reader) {
    char bytes[4096];
    while (!atomic_load(&shared->stop)) {
      if (pread(source, bytes, sizeof(bytes), 0) < 0) {
        atomic_store(&shared->error, errno);
        _exit(1);
      }
      atomic_fetch_add(&shared->reads, 1);
    }
    _exit(0);
  }
  while (!atomic_load(&shared->reads) && !atomic_load(&shared->error))
    CHECK(sched_yield() == 0);
  CHECK(atomic_load(&shared->error) == 0);
  posix_spawn_file_actions_t actions;
  CHECK(posix_spawn_file_actions_init(&actions) == 0);
  CHECK(posix_spawn_file_actions_addclose(&actions, 49) == 0);
  CHECK(posix_spawn_file_actions_addclose(&actions, 49) == 0);
  CHECK(posix_spawn_file_actions_addopen(&actions, 48, path,
                                       O_RDWR | O_TRUNC | O_CLOEXEC, 0600) == 0);
  CHECK(posix_spawn_file_actions_adddup2(&actions, 48, 48) == 0);
  CHECK(posix_spawn_file_actions_adddup2(&actions, 48, 52) == 0);
  CHECK(posix_spawn_file_actions_addopen(&actions, 50, "/tmp",
                                       O_RDONLY | O_DIRECTORY, 0) == 0);
  CHECK(posix_spawn_file_actions_addfchdir_np(&actions, 50) == 0);
  CHECK(posix_spawn_file_actions_addclose(&actions, 50) == 0);
  CHECK(posix_spawn_file_actions_addopen(&actions, 51, strrchr(path, '/') + 1,
                                       O_RDWR, 0) == 0);
  char *arguments[] = {"spawn-admission", "--verify", NULL};
  for (unsigned iteration = 0; iteration < 8; ++iteration) {
    CHECK(ftruncate(source, 8192) == 0);
    pid_t child;
    int error = posix_spawn(&child, "/system/services/compositor.service",
                           &actions, NULL, arguments, environ);
    if (error) errno = error;
    CHECK(error == 0);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
          WEXITSTATUS(status) == 0);
    CHECK(fcntl(48, F_GETFD) == FD_CLOEXEC);
    char cwd[256];
    CHECK(getcwd(cwd, sizeof(cwd)) && strcmp(cwd, initial_cwd) == 0);
    fprintf(stderr, "spawn-file-admission: completed child %u\n", iteration);
  }
  atomic_store(&shared->stop, 1);
  int status;
  CHECK(waitpid(reader, &status, 0) == reader && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  CHECK(atomic_load(&shared->error) == 0 && atomic_load(&shared->reads) != 0);
  CHECK(posix_spawn_file_actions_destroy(&actions) == 0);
  CHECK(close(48) == 0 && close(source) == 0 && unlink(path) == 0);
  printf("spawn-file-admission: PASS 8 children; exact target, CLOEXEC, dup "
         "offsets, fchdir and relative open (%u concurrent reads)\n",
         atomic_load(&shared->reads));
  CHECK(munmap(shared, 4096) == 0);
  return 0;
}
