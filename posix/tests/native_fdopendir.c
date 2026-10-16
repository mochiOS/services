/* Adoption preserves the original FD, shared provider cursor and FD flags. */
#define main directory_baseline_main
#include "native_directory_io.c"
#undef main

static int collect(DIR *stream, unsigned char seen[FILE_COUNT],
                   unsigned *count) {
  for (;;) {
    errno = 0;
    struct dirent *entry = readdir(stream);
    if (!entry) {
      CHECK(errno == 0);
      return 0;
    }
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      continue;
    unsigned index = FILE_COUNT;
    CHECK(sscanf(entry->d_name, "file-%u", &index) == 1);
    CHECK(index < FILE_COUNT && !seen[index]);
    seen[index] = 1;
    ++*count;
  }
}

int main(void) {
  char directory[96], path[128];
  snprintf(directory, sizeof(directory), "/tmp/fdopendir-%d", (int)getpid());
  CHECK(mkdir(directory, 0700) == 0);
  for (unsigned index = 0; index < FILE_COUNT; ++index) {
    snprintf(path, sizeof(path), "%s/file-%03u", directory, index);
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(fd >= 0 && close(fd) == 0);
  }
  int64_t baseline = native_count();
  errno = 0;
  CHECK(fdopendir(-1) == NULL && errno == EBADF);
  int regular = open(path, O_RDONLY);
  CHECK(regular >= 0);
  errno = 0;
  CHECK(fdopendir(regular) == NULL && errno == ENOTDIR);
  CHECK(fcntl(regular, F_GETFD) >= 0 && close(regular) == 0);
  int pipes[2];
  CHECK(pipe(pipes) == 0);
  errno = 0;
  CHECK(fdopendir(pipes[0]) == NULL && errno == ENOTDIR);
  CHECK(close(pipes[0]) == 0 && close(pipes[1]) == 0);
  CHECK(native_count() == baseline);

  for (unsigned flags = 0; flags <= FD_CLOEXEC; ++flags) {
    DIR *first = opendir(directory);
    CHECK(first != NULL);
    struct dirent *entry;
    do {
      entry = readdir(first);
    } while (entry &&
             (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")));
    CHECK(entry != NULL);
    unsigned index = FILE_COUNT;
    CHECK(sscanf(entry->d_name, "file-%u", &index) == 1 && index < FILE_COUNT);
    unsigned char seen[FILE_COUNT] = {0};
    seen[index] = 1;
    unsigned count = 1;
    int original = dirfd(first);
    int fd = dup(original);
    CHECK(fd >= 0 && fcntl(fd, F_SETFD, flags) == 0);
    int64_t before = native_count();
    DIR *second = fdopendir(fd);
    CHECK(second != NULL && dirfd(second) == fd);
    CHECK(fcntl(fd, F_GETFD) == (int)flags && native_count() == before);
    CHECK(collect(second, seen, &count) == 0);
    /* The first DIR prefetches less than the entire directory. Adopting its
       alias must start after that prefetch, not reopen at the beginning. */
    CHECK(count > 1 && count < FILE_COUNT);
    CHECK(closedir(second) == 0);
    errno = 0;
    CHECK(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
    CHECK(fcntl(original, F_GETFD) >= 0);
    CHECK(collect(first, seen, &count) == 0 && count == FILE_COUNT);
    CHECK(closedir(first) == 0 && native_count() == baseline);
  }
  for (unsigned index = 0; index < FILE_COUNT; ++index) {
    snprintf(path, sizeof(path), "%s/file-%03u", directory, index);
    CHECK(unlink(path) == 0);
  }
  CHECK(rmdir(directory) == 0 && native_count() == baseline);
  puts("fdopendir: PASS failure ownership, CLOEXEC, shared cursor and close");
  return 0;
}
