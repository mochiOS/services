#include <pthread.h>
#include <stdatomic.h>
#define main run_stream_regressions
#include "native_socket_pair.c"
#undef main

static _Atomic uint32_t parent_object;
static _Atomic int foreign_error;
static int foreign_work(void) {
  int64_t endpoint = native(629, 0, 0, 0, 0, 0, 0);
  CHECK(endpoint > 0);
  CHECK((int64_t)native(691, 42, 0, 0, 0, 0, 0) == INT64_C(-262139));
  CHECK((int64_t)native(638, atomic_load(&parent_object), 0, 0, 0, 0, 0) ==
        INT64_C(-262138));
  int64_t own = native(637, endpoint, 42, 1, 0, 0, 0);
  CHECK(own > 0 && native(691, 42, 0, 0, 0, 0, 0) == 1);
  CHECK(native(626, own, 0, 0, 0, 0, 0) == 0);
  CHECK((int64_t)native(691, 42, 0, 0, 0, 0, 0) == INT64_C(-262139));
  CHECK(native(626, endpoint, 0, 0, 0, 0, 0) == 0);
  return 0;
}
static void *foreign(void *unused) {
  (void)unused;
  atomic_store(&foreign_error, foreign_work());
  return NULL;
}
int main(void) {
  CHECK(run_stream_regressions() == 0);
  int64_t endpoint = native(629, 0, 0, 0, 0, 0, 0);
  CHECK(endpoint > 0);
  CHECK((int64_t)native(638, endpoint, 0, 0, 0, 0, 0) == INT64_C(-262139));
  CHECK((int64_t)native(638, 0, 0, 0, 0, 0, 0) == INT64_C(-262139));
  CHECK((int64_t)native(638, (UINT64_C(1) << 32) | endpoint, 0, 0, 0, 0, 0) ==
        INT64_C(-262139));
  uint64_t rights = (UINT64_C(3) << 62) | 1;
  int64_t object = native(637, endpoint, 42, rights, 0, 0, 0);
  CHECK(object > 0 && native(691, 42, 0, 0, 0, 0, 0) == 1);
  CHECK(native(638, object, 0, 0, 0, 0, 0) == 42);
  int64_t metadata_only = native(627, object, 0, 0, 0, 0, 0);
  CHECK(metadata_only > 0 && native(638, metadata_only, 0, 0, 0, 0, 0) == 42);
  CHECK(native(626, metadata_only, 0, 0, 0, 0, 0) == 0);
  atomic_store(&parent_object, object);
  int64_t alias = native(627, object, 1, 0, 0, 0, 0);
  CHECK(alias > 0 && native(691, 42, 0, 0, 0, 0, 0) == 2);
  pthread_t worker;
  CHECK(pthread_create(&worker, NULL, foreign, NULL) == 0);
  CHECK(pthread_join(worker, NULL) == 0 && !atomic_load(&foreign_error));
  CHECK(native(691, 42, 0, 0, 0, 0, 0) == 2);
  CHECK(native(626, alias, 0, 0, 0, 0, 0) == 0);
  CHECK(native(691, 42, 0, 0, 0, 0, 0) == 1);
  struct handles attached = {1, 0, {{object, 0, 1}}};
  CHECK((int64_t)native(630, endpoint, (uintptr_t) "queued", 6,
                        (uintptr_t)&attached, 0, 0) >= 0);
  CHECK(native(691, 42, 0, 0, 0, 0, 0) == 2);
  char bytes[64];
  attached.count = 0;
  CHECK((int64_t)native(631, (uintptr_t)bytes, sizeof(bytes),
                        (uintptr_t)&attached, endpoint, 0, 0) >= 0);
  CHECK(attached.count == 1 && attached.entries[0].rights == 1);
  CHECK(native(638, attached.entries[0].handle, 0, 0, 0, 0, 0) == 42);
  CHECK(native(691, 42, 0, 0, 0, 0, 0) == 2);
  CHECK(native(626, attached.entries[0].handle, 0, 0, 0, 0, 0) == 0);
  CHECK(native(691, 42, 0, 0, 0, 0, 0) == 1);
  CHECK((int64_t)native(691, 0, 0, 0, 0, 0, 0) == INT64_C(-262139));
  int64_t zero = native(637, endpoint, 0, 1, 0, 0, 0);
  CHECK(zero > 0 && native(691, 0, 0, 0, 0, 0, 0) == 1);
  CHECK(native(626, zero, 0, 0, 0, 0, 0) == 0);
  CHECK((int64_t)native(691, UINT64_MAX, 0, 0, 0, 0, 0) == INT64_C(-262139));
  CHECK(native(626, object, 0, 0, 0, 0, 0) == 0);
  CHECK((int64_t)native(638, object, 0, 0, 0, 0, 0) == INT64_C(-262139));
  CHECK((int64_t)native(691, 42, 0, 0, 0, 0, 0) == INT64_C(-262139));
  CHECK(native(626, endpoint, 0, 0, 0, 0, 0) == 0);
  puts("provider-reference-count: PASS aliases, queued IPC leases, release, "
       "exact endpoint namespace, no query pin");
  fflush(stdout);
  return 0;
}
