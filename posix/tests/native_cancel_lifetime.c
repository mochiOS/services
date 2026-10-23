/* Actual pthread cancellation publication and generation reuse. */
#define main process_cpu_regression
#include "native_cpu_sleep.c"
#undef main

static sem_t cancel_ready, cancel_gate;
static void *return_immediately(void *unused) { (void)unused;return (void *)7; }
static void *await_cancellation(void *unused) {
  (void)unused;
  if (sem_post(&cancel_ready) || sem_wait(&cancel_gate)) return (void *)1;
  pthread_testcancel();return (void *)9;
}
#ifndef CANCEL_LIFETIME_ENTRY
#define CANCEL_LIFETIME_ENTRY main
#endif
int CANCEL_LIFETIME_ENTRY(void) {
  CHECK(process_cpu_regression()==0);
  CHECK(sem_init(&cancel_ready,0,0)==0 && sem_init(&cancel_gate,0,0)==0);
  for (unsigned round=0;round<32;++round) {
    pthread_t old,replacement;void *value=NULL;
    CHECK(pthread_create(&old,NULL,return_immediately,NULL)==0);
    CHECK(pthread_join(old,&value)==0 && value==(void *)7);
    CHECK(pthread_create(&replacement,NULL,await_cancellation,NULL)==0);
    CHECK(replacement!=old && sem_wait(&cancel_ready)==0);
    CHECK(pthread_cancel(old)==ESRCH);
    CHECK(sem_post(&cancel_gate)==0);
    CHECK(pthread_join(replacement,&value)==0 && value==(void *)9);
  }
  fputs("cancel-lifetime: PASS 32 stale tokens cannot cancel reused slots\n",stderr);
  for (unsigned round=0;round<32;++round) {
    pthread_t worker;void *value=NULL;
    CHECK(pthread_create(&worker,NULL,await_cancellation,NULL)==0);
    /* No readiness wait: publication may precede the worker trampoline. */
    CHECK(pthread_cancel(worker)==0);
    CHECK(pthread_join(worker,&value)==0 && value==PTHREAD_CANCELED);
    CHECK(sem_wait(&cancel_ready)==0);
  }
  CHECK(sem_destroy(&cancel_ready)==0 && sem_destroy(&cancel_gate)==0);
  fputs("cancel-lifetime: PASS 32 immediately canceled published threads and existing CPU sleep regressions\n",stderr);
  return 0;
}
