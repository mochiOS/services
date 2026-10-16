/* Real libc bookmarks across prefetch, EOF, hidden entries and FD adoption. */
#define main directory_baseline_main
#include "native_directory_io.c"
#undef main

enum { VISIBLE_FILES = 180, RECORDS = 200 };
int main(void) {
  char directory[96], renamed[96], path[128];
  snprintf(directory, sizeof(directory), "/tmp/dir-position-%d", (int)getpid());
  snprintf(renamed, sizeof(renamed), "/tmp/dir-position-moved-%d",
           (int)getpid());
  CHECK(mkdir(directory, 0700) == 0);
  for (unsigned index = 0; index < VISIBLE_FILES; ++index) {
    snprintf(path, sizeof(path), "%s/file-%03u", directory, index);
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    CHECK(fd >= 0 && close(fd) == 0);
  }
  snprintf(path, sizeof(path), "%s/removed", directory);
  int orphan = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
  CHECK(orphan >= 0 && unlink(path) == 0);
  snprintf(path, sizeof(path), "%s/last", directory);
  int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
  CHECK(fd >= 0 && close(fd) == 0);
  int64_t baseline = native_count();
  DIR *stream = opendir(directory);
  CHECK(stream != NULL && telldir(stream) == 0);
  long positions[RECORDS];
  char names[RECORDS][256];
  unsigned count = 0, files = 0;
  for (;;) {
    CHECK(count < RECORDS);
    positions[count] = telldir(stream);
    CHECK(positions[count] >= 0);
    errno = 0;
    struct dirent *entry = readdir(stream);
    if (!entry) {
      CHECK(errno == 0);
      break;
    }
    strcpy(names[count++], entry->d_name);
    if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
      unsigned index;
      CHECK(!strcmp(entry->d_name, "last") ||
            (sscanf(entry->d_name, "file-%u", &index) == 1 &&
             index < VISIBLE_FILES));
      ++files;
    }
  }
  CHECK(files == VISIBLE_FILES + 1);
  long eof = telldir(stream);
  CHECK(eof >= 0 && positions[count] == eof);
  CHECK(rename(directory, renamed) == 0);
  unsigned samples[] = {0, 1, 7, count / 2, count - 1};
  for (unsigned sample = 0; sample < sizeof(samples) / sizeof(samples[0]);
       ++sample) {
    unsigned index = samples[sample];
    errno = 0;
    seekdir(stream, positions[index]);
    CHECK(errno == 0 && telldir(stream) == positions[index]);
    struct dirent *entry = readdir(stream);
    CHECK(entry != NULL && !strcmp(entry->d_name, names[index]));
  }
  seekdir(stream, eof);
  errno = 0;
  CHECK(readdir(stream) == NULL && errno == 0 && telldir(stream) == eof);
  unsigned middle = count / 2;
  seekdir(stream, positions[middle]);
  int alias = dup(dirfd(stream));
  CHECK(alias >= 0);
  DIR *adopted = fdopendir(alias);
  CHECK(adopted != NULL && telldir(adopted) == positions[middle]);
  struct dirent *entry = readdir(adopted);
  CHECK(entry != NULL && !strcmp(entry->d_name, names[middle]));
  CHECK(closedir(adopted) == 0);
  seekdir(stream, positions[1]);
  errno = 0;
  seekdir(stream, -1);
  CHECK(errno == EINVAL && telldir(stream) == positions[1]);
  rewinddir(stream);
  CHECK(telldir(stream) == 0);
  CHECK(closedir(stream) == 0 && native_count() == baseline);
  CHECK(close(orphan) == 0);
  for (unsigned index = 0; index < VISIBLE_FILES; ++index) {
    snprintf(path, sizeof(path), "%s/file-%03u", renamed, index);
    CHECK(unlink(path) == 0);
  }
  snprintf(path, sizeof(path), "%s/last", renamed);
  CHECK(unlink(path) == 0 && rmdir(renamed) == 0);
  CHECK(native_count() == baseline - 1);
  puts("directory-position: PASS prefetch, EOF, hidden-entry cookies, rename, "
       "adopted FD, rewind and reference recovery");
  return 0;
}
