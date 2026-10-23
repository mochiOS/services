/* Real native upcall cancellation without application signal reservation. */
#define CANCEL_LIFETIME_ENTRY deferred_lifetime_regression
#include "native_cancel_lifetime.c"
#undef CANCEL_LIFETIME_ENTRY

struct async_context {
  unsigned mode;
  atomic_int ready, release, returned, error, cleaned, destroyed, inner;
  int previous_type, previous_state;
};
static pthread_key_t async_key;
static struct async_context async_contexts[24];
static void async_destructor(void *pointer) {
  struct async_context *context=pointer;
  atomic_fetch_add(&context->destroyed,1);
}
static void async_cleanup(void *pointer) {
  struct async_context *context=pointer;int old=-1;
  if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old) || old!=PTHREAD_CANCEL_DISABLE)
    atomic_store(&context->error,9);
  atomic_fetch_add(&context->cleaned,1);
}
static void async_inner(void *pointer) {
  struct async_context *context=pointer;atomic_fetch_add(&context->inner,1);
}
static void *async_worker(void *pointer) {
  struct async_context *context=pointer;
  pthread_t self=pthread_self();
  if (pthread_setspecific(async_key,context)) return (void *)1;
  sigset_t blocked;
  if (sigfillset(&blocked) || pthread_sigmask(SIG_SETMASK,&blocked,NULL)) return (void *)1;
  pthread_cleanup_push(async_cleanup,context);
  if (context->mode==1 || context->mode==2) {
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&context->previous_state)) atomic_store(&context->error,1);
  }
  if (context->mode==0 || context->mode==1 || context->mode>=4) {
    if (pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,&context->previous_type)) atomic_store(&context->error,2);
  }
  struct _pthread_cleanup_context inner;
  if (context->mode==5) _pthread_cleanup_push_defer(&inner,async_inner,context);
  atomic_store_explicit(&context->ready,1,memory_order_release);
  if (context->mode==4) {
    (void)pthread_cancel(self);
  } else if (context->mode==0) {
    /* No POSIX function or cancellation point in this compute loop. */
    for (;;) atomic_signal_fence(memory_order_seq_cst);
  } else {
    while (!atomic_load_explicit(&context->release,memory_order_acquire)) atomic_signal_fence(memory_order_seq_cst);
    if (context->mode==2 || context->mode==3) {
      if (pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,&context->previous_type)) atomic_store(&context->error,3);
    }
    if (context->mode==1 || context->mode==2) {
      if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,&context->previous_state)) atomic_store(&context->error,4);
    }
    if (context->mode==5) _pthread_cleanup_pop_restore(&inner,0);
  }
  atomic_store(&context->returned,1);
  pthread_cleanup_pop(1);
  return (void *)2;
}
int main(void) {
  CHECK(deferred_lifetime_regression()==0);
  CHECK(pthread_key_create(&async_key,async_destructor)==0);
  CHECK(alarm(20)==0);
  for (unsigned round=0;round<24;++round) {
    struct async_context *context=&async_contexts[round];context->mode=round%6;
    pthread_t worker;void *value=NULL;
    CHECK(pthread_create(&worker,NULL,async_worker,context)==0);
    while (!atomic_load_explicit(&context->ready,memory_order_acquire)) sched_yield();
    CHECK(!atomic_load(&context->error));
    if (context->mode!=4) CHECK(pthread_cancel(worker)==0);
    atomic_store_explicit(&context->release,1,memory_order_release);
    CHECK(pthread_join(worker,&value)==0 && value==PTHREAD_CANCELED);
    CHECK(!atomic_load(&context->returned) && !atomic_load(&context->error));
    CHECK(atomic_load(&context->cleaned)==1 && atomic_load(&context->destroyed)==1 && !atomic_load(&context->inner));
    CHECK(context->previous_type==PTHREAD_CANCEL_DEFERRED);
    if (context->mode==1 || context->mode==2) CHECK(context->previous_state==PTHREAD_CANCEL_DISABLE);
    if (round>=18) fprintf(stderr,"async-cancel: PASS mode=%u compute, state/type transition, self or cleanup restore\n",context->mode);
  }
  CHECK(pthread_key_delete(async_key)==0);(void)alarm(0);return 0;
}
