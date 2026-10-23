#include <errno.h>
#include <limits.h>
#include <pthread.h>

static void *set_from_another_thread(void *unused) {
  (void)unused;
  errno = 321;
  if (pthread_getconcurrency() != 7 || pthread_setconcurrency(11) != 0 ||
      pthread_getconcurrency() != 11 || errno != 321)
    return (void *)1;
  return 0;
}

int main(void) {
  if (pthread_getconcurrency() != 0)
    return 1;
  errno = 123;
  if (pthread_setconcurrency(7) || pthread_getconcurrency() != 7 ||
      pthread_setconcurrency(-1) != EINVAL || pthread_getconcurrency() != 7 ||
      errno != 123)
    return 2;
  pthread_t worker;
  void *result;
  if (pthread_create(&worker, 0, set_from_another_thread, 0) ||
      pthread_join(worker, &result) || result || pthread_getconcurrency() != 11)
    return 3;
  if (pthread_setconcurrency(INT_MAX) || pthread_getconcurrency() != INT_MAX ||
      pthread_setconcurrency(0) || pthread_getconcurrency() != 0)
    return 4;
  return 0;
}
