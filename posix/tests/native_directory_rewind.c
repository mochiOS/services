/* Rewind the retained description, not a new lookup of its former path. */
#define main directory_baseline_main
#include "native_directory_io.c"
#undef main

static int entries(DIR *stream, unsigned expected) {
  unsigned count = 0;
  for (;;) {
    errno = 0;
    struct dirent *entry = readdir(stream);
    if (!entry) {
      CHECK(errno == 0);
      break;
    }
    if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
      ++count;
  }
  CHECK(count == expected);
  return 0;
}

int main(void) {
  char directory[96], renamed[96], path[128];
  snprintf(directory, sizeof(directory), "/tmp/rewinddir-%d", (int)getpid());
  snprintf(renamed, sizeof(renamed), "/tmp/rewound-%d", (int)getpid());
  CHECK(mkdir(directory, 0700) == 0);
  for (unsigned index = 0; index < 3; ++index) {
    snprintf(path, sizeof(path), "%s/file-%03u", directory, index);
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    CHECK(fd >= 0 && close(fd) == 0);
  }
  int64_t baseline = native_count();
  DIR *stream = opendir(directory);
  CHECK(stream != NULL);
  int fd = dirfd(stream);
  int alias = dup(fd);
  CHECK(alias >= 0);
  int64_t opened = native_count();
  struct dirent *first = readdir(stream);
  CHECK(first != NULL);
  char name[256];
  strcpy(name, first->d_name);
  CHECK(readdir(stream) != NULL);
  errno = 0;
  rewinddir(stream);
  CHECK(errno == 0 && native_count() == opened);
  first = readdir(stream);
  CHECK(first != NULL && !strcmp(first->d_name, name));
  rewinddir(stream);
  CHECK(entries(stream, 3) == 0);
  CHECK(rename(directory, renamed) == 0);
  snprintf(path, sizeof(path), "%s/file-003", renamed);
  int created = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
  CHECK(created >= 0 && close(created) == 0);
  errno = 0;
  rewinddir(stream);
  CHECK(errno == 0 && fcntl(fd, F_GETFD) == FD_CLOEXEC);
  CHECK(entries(stream, 4) == 0);
  /* A second DIR on the alias observes the same rewound provider cursor. */
  rewinddir(stream);
  DIR *second = fdopendir(alias);
  CHECK(second != NULL && entries(second, 4) == 0);
  CHECK(closedir(second) == 0 && closedir(stream) == 0);
  CHECK(native_count() == baseline);
  for (unsigned index = 0; index < 4; ++index) {
    snprintf(path, sizeof(path), "%s/file-%03u", renamed, index);
    CHECK(unlink(path) == 0);
  }
  CHECK(rmdir(renamed) == 0 && native_count() == baseline);
  puts("rewinddir: PASS prefetch/EOF invalidation, rename, mutation, shared "
       "cursor and reference recovery");
  return 0;
}
