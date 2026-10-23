/* Actual libc callbacks, detached pthread lifetime, re-entry and fork. */
#define main unused_cpu_sleep_baseline
#include "native_cpu_sleep.c"
#undef main
#include <string.h>

struct context { sem_t done; timer_t timer; int mode; atomic_int calls, failure; };
static struct context contexts[80];
static pthread_t creator;
static void notified(union sigval value) {
  struct context *context=value.sival_ptr;
  if (pthread_equal(pthread_self(),creator)) atomic_store(&context->failure,1);
  atomic_fetch_add(&context->calls,1);
  if (context->mode==1) {
    struct sigevent silent={.sigev_notify=SIGEV_NONE};timer_t other;
    if (timer_delete(context->timer) || timer_create(CLOCK_MONOTONIC,&silent,&other) || timer_delete(other))
      atomic_store(&context->failure,2);
  }
  if (sem_post(&context->done)) atomic_store(&context->failure,3);
  if (context->mode==1) pthread_exit(NULL);
}
static int once(unsigned index,clockid_t clock,int mode,pthread_attr_t *attributes) {
  struct context *context=&contexts[index];context->mode=mode;
  CHECK(sem_init(&context->done,0,0)==0);
  struct sigevent event={.sigev_notify=SIGEV_THREAD,.sigev_value.sival_ptr=context,
    .sigev_notify_function=notified,.sigev_notify_attributes=attributes};
  CHECK(timer_create(clock,&event,&context->timer)==0);
  if (attributes) { CHECK(pthread_attr_destroy(attributes)==0);memset(attributes,0xff,sizeof(*attributes)); }
  struct itimerspec setting={.it_value={0,1000000}};
  CHECK(timer_settime(context->timer,0,&setting,NULL)==0);
  if (clock==CLOCK_PROCESS_CPUTIME_ID || clock==CLOCK_THREAD_CPUTIME_ID) burn_until(cpu()+50000000);
  CHECK(sem_wait(&context->done)==0);
  CHECK(atomic_load(&context->calls)==1 && !atomic_load(&context->failure));
  if (mode!=1) CHECK(timer_delete(context->timer)==0);
  CHECK(sem_destroy(&context->done)==0);
  return 0;
}
int main(void) {
  creator=pthread_self();CHECK(alarm(20)==0);
  CHECK(once(0,CLOCK_MONOTONIC,0,NULL)==0);
  pthread_attr_t attributes;
  CHECK(pthread_attr_init(&attributes)==0 && pthread_attr_setstacksize(&attributes,65536)==0);
  CHECK(once(1,CLOCK_MONOTONIC,1,&attributes)==0);
  CHECK(once(2,CLOCK_PROCESS_CPUTIME_ID,0,NULL)==0);
  CHECK(once(3,CLOCK_THREAD_CPUTIME_ID,0,NULL)==0);
  struct sigevent bad={.sigev_notify=SIGEV_THREAD,.sigev_notify_function=notified};
  for (unsigned index=0;index<140;++index) {
    CHECK(timer_create(CLOCK_MONOTONIC,&bad,(timer_t *)(uintptr_t)1)==-1 && errno==EFAULT);
  }
  fputs("sigev-thread: PASS callback value, copied attributes, re-entry, pthread_exit and CPU clocks\n",stderr);
  for (unsigned index=4;index<68;++index) CHECK(once(index,CLOCK_MONOTONIC,index%2,NULL)==0);
  fputs("sigev-thread: PASS 64 repeated detached callbacks without exhausting runtime slots\n",stderr);
  pid_t child=fork();CHECK(child>=0);
  if (!child) {
    creator=pthread_self();if (once(68,CLOCK_MONOTONIC,1,NULL)) _exit(82);
    /* The hidden receiver must not keep this child alive. */
    pthread_exit(NULL);
  }
  int status;CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
  CHECK(once(69,CLOCK_MONOTONIC,0,NULL)==0);
  fputs("sigev-thread: PASS fork resets receiver, last application pthread exits process, parent remains live\n",stderr);
  (void)alarm(0);return 0;
}
