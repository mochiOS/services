/* Concurrent native I/O must not turn blocking metadata operations into
 * EAGAIN or stall the POSIX service that the reader needs to complete.
 * This is also the regression for admission starvation: continuous reads
 * must not indefinitely overtake a pending extent update. Do not cap reader
 * iterations or add a delay to make that scheduling failure disappear. */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "file-admission: FAIL line %u errno=%d: %s\n", __LINE__, \
              errno, #x);                                                      \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static atomic_int stop_reader;
static atomic_int reader_error;
static atomic_uint reads;
static int source;

static void *read_file(void *unused) {
  (void)unused;
  char bytes[4096];
  while (!atomic_load(&stop_reader)) {
    if (pread(source, bytes, sizeof(bytes), 0) < 0) {
      atomic_store(&reader_error, errno);
      break;
    }
    atomic_fetch_add(&reads, 1);
  }
  return NULL;
}

int main(void) {
  fprintf(stderr, "file-admission: starting concurrent I/O checks\n");
  char path[] = "/tmp/file-admission-XXXXXX";
  source = mkstemp(path);
  CHECK(source >= 0);
  CHECK(ftruncate(source, 8192) == 0);
  fprintf(stderr, "file-admission: initial extent ready\n");
  pthread_t reader;
  CHECK(pthread_create(&reader, NULL, read_file, NULL) == 0);
  fprintf(stderr, "file-admission: reader created\n");
  unsigned waiting = 0;
  while (!atomic_load(&reads) && !atomic_load(&reader_error) &&
         waiting++ < 10000)
    CHECK(sched_yield() == 0);
  CHECK(atomic_load(&reads) != 0 && atomic_load(&reader_error) == 0);
  fprintf(stderr, "file-admission: reader active\n");
  for (unsigned i = 0; i < 64; ++i) {
    CHECK(ftruncate(source, i % 2 ? 8192 : 5000) == 0);
    if (i % 8 == 0) {
      int opened = open(path, O_RDWR | O_TRUNC);
      CHECK(opened >= 0);
      CHECK(close(opened) == 0);
      CHECK(truncate(path, 8192) == 0);
      fprintf(stderr, "file-admission: completed iteration %u\n", i);
    }
  }
  atomic_store(&stop_reader, 1);
  CHECK(pthread_join(reader, NULL) == 0);
  CHECK(atomic_load(&reader_error) == 0);
  CHECK(close(source) == 0 && unlink(path) == 0);
  printf("file-admission: PASS concurrent pread/ftruncate/truncate/O_TRUNC (%u "
         "reads)\n",
         atomic_load(&reads));
  return 0;
}
