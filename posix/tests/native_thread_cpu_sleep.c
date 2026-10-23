#define CPU_SLEEP_FORK_ENTRY process_sleep_regression
#include "native_cpu_sleep_fork.c"
#undef CPU_SLEEP_FORK_ENTRY

static sem_t target_gate, target_release;
static clockid_t target_clock;
static unsigned target_mode;
static struct timespec target_request, target_remaining;
static int target_flags, target_result, target_errno;
static atomic_int target_done, target_error;

static uint64_t thread_cpu(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &value)) return UINT64_MAX;
  return nanos(value);
}
static void *cpu_subject(void *unused) {
  (void)unused;
  if (sem_wait(&target_gate)) { atomic_store(&target_error,1); return NULL; }
  if (target_mode < 2) {
    uint64_t deadline=thread_cpu()+150000000;
    while (thread_cpu()<deadline) for (volatile unsigned n=0;n<100000;++n) {}
  }
  if (target_mode<=2 && sem_wait(&target_release)) atomic_store(&target_error,2);
  return NULL;
}
static void *thread_clock_waiter(void *unused) {
  (void)unused;
  pthread_cleanup_push(cleanup,NULL);
  struct timespec remaining={99,99};
  errno=EDOM;
  target_result=clock_nanosleep(target_clock,target_flags,&target_request,&remaining);
  target_errno=errno;
  target_remaining=remaining;
  atomic_store_explicit(&target_done,1,memory_order_release);
  pthread_cleanup_pop(0);
  return NULL;
}

int main(void) {
  CHECK(process_sleep_regression()==0);
  clockid_t own_thread;
  CHECK(pthread_getcpuclockid(pthread_self(),&own_thread)==0);
  struct timespec zero={0,0}, untouched={99,99};
  errno=EDOM;
  CHECK(clock_nanosleep(own_thread,0,&zero,&untouched)==EINVAL && errno==EDOM);
  CHECK(clock_nanosleep(CLOCK_THREAD_CPUTIME_ID,0,&zero,&untouched)==EINVAL && errno==EDOM);
  CHECK(untouched.tv_sec==99 && untouched.tv_nsec==99);

  for (target_mode=0;target_mode<5;++target_mode) {
    CHECK(sem_init(&target_gate,0,0)==0 && sem_init(&target_release,0,0)==0);
    atomic_store(&target_done,0);atomic_store(&target_error,0);atomic_store(&cleaned,0);atomic_store(&error,0);
    pthread_t source,waiter;
    CHECK(pthread_create(&source,NULL,cpu_subject,NULL)==0);
    CHECK(pthread_getcpuclockid(source,&target_clock)==0);
    struct timespec before;
    CHECK(clock_gettime(target_clock,&before)==0);
    target_flags=target_mode==1 ? TIMER_ABSTIME : 0;
    target_request=timespec(target_mode==1 ? nanos(before)+50000000
                            : target_mode==0 ? 50000000 : 100000000000);
    CHECK(pthread_create(&waiter,NULL,thread_clock_waiter,NULL)==0);
    uint64_t label=0,started=cpu();
    while (!(label=find_private())) {
      CHECK(!atomic_load(&target_done) && cpu()-started<5000000000);
      sched_yield();
    }
    CHECK(label!=UINT64_MAX);atomic_store(&private_label,label);
    CHECK(alarm(10)==0);
    if (target_mode<2) {
      burn_until(cpu()+100000000);
      CHECK(!atomic_load_explicit(&target_done,memory_order_acquire));
      CHECK(sem_post(&target_gate)==0);
    } else if (target_mode==2) {
      CHECK(pthread_kill(waiter,SIGUSR1)==0);
    } else if (target_mode==3) {
      CHECK(sem_post(&target_gate)==0);
    } else {
      pid_t child=-1;
      for (unsigned attempt=0;attempt<100;++attempt) {
        child=fork();
        if (child>=0 || errno!=EAGAIN) break;
        struct timespec pause={0,10000000};CHECK(nanosleep(&pause,NULL)==0);
      }
      CHECK(child>=0);
      if (!child) {
        struct timespec value;
        if (native(664,label,0)==17 || clock_gettime(target_clock,&value)!=-1 || errno!=EINVAL) _exit(81);
        _exit(0);
      }
      int status;
      CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
      CHECK(pthread_cancel(waiter)==0);
    }
    void *result=NULL;
    CHECK(pthread_join(waiter,&result)==0);
    if (target_mode==4) {
      CHECK(result==PTHREAD_CANCELED && atomic_load(&cleaned)==1 && !atomic_load(&error));
    } else {
      CHECK(result==NULL && target_errno==EDOM);
      CHECK(target_result==(target_mode==2 ? EINTR : target_mode==3 ? EINVAL : 0));
      if (target_mode==2) CHECK(target_remaining.tv_sec>0 && nanos(target_remaining)<=100000000000);
      else CHECK(target_remaining.tv_sec==99 && target_remaining.tv_nsec==99);
    }
    (void)alarm(0);
    if (target_mode<2) {
      struct timespec after;
      CHECK(clock_gettime(target_clock,&after)==0 && nanos(after)>=nanos(before)+50000000);
    }
    if (target_mode==2 || target_mode==4) CHECK(sem_post(&target_gate)==0);
    if (target_mode<=2) CHECK(sem_post(&target_release)==0);
    CHECK(pthread_join(source,&result)==0 && result==NULL && !atomic_load(&target_error));
    CHECK(clock_nanosleep(target_clock,0,&zero,NULL)==EINVAL);
    CHECK(sem_destroy(&target_gate)==0 && sem_destroy(&target_release)==0);
    fprintf(stderr,"thread-cpu-sleep: PASS mode=%u selected-thread accounting, lifetime and resource cleanup\n",target_mode);
  }
  return 0;
}
