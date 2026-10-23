/* Actual newlib clock_nanosleep, cancellation and COW/fork integration. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(test) do { if (!(test)) { \
  fprintf(stderr, "cpu-sleep-libc: FAIL line=%d errno=%d: %s\n", __LINE__, errno, #test); \
  return 1; } } while (0)
static int64_t native(uint64_t number, uint64_t a, uint64_t b) {
  __asm__ volatile("syscall" : "+a"(number) : "D"(a), "S"(b) : "rcx", "r11", "memory");
  return (int64_t)number;
}
static uint64_t nanos(struct timespec time) {
  return (uint64_t)time.tv_sec * 1000000000 + (uint64_t)time.tv_nsec;
}
static struct timespec timespec(uint64_t ns) {
  return (struct timespec){ns / 1000000000, ns % 1000000000};
}
static uint64_t cpu(void) {
  struct timespec time;
  if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time)) return UINT64_MAX;
  return nanos(time);
}
static void burn_until(uint64_t deadline) {
  while (cpu() < deadline) {
    for (volatile unsigned n = 0; n < 100000; ++n) {}
  }
}
static sem_t gate;
static uint64_t burn_deadline;
static void *burn(void *unused) {
  (void)unused;
  if (sem_wait(&gate)) return (void *)1;
  burn_until(burn_deadline);
  return NULL;
}
static pthread_t main_thread;
static volatile sig_atomic_t caught;
static void handler(int signal) { if (signal == SIGUSR1) ++caught; }
static void *interrupt_sleep(void *unused) {
  (void)unused;
  struct timespec pause = {0, 30000000};
  if (nanosleep(&pause, NULL) || pthread_kill(main_thread, SIGUSR1)) return (void *)1;
  return NULL;
}
static atomic_int ready, error, cleaned;
static atomic_uint_fast64_t private_label;
static void cleanup(void *unused) {
  (void)unused;
  /* Application cleanup must observe the completion reference already gone. */
  if (native(664, atomic_load(&private_label), 0) >= 0) atomic_store(&error, 2);
  atomic_fetch_add(&cleaned, 1);
}
static void *cancel_sleep(void *disabled) {
  int result;
  pthread_cleanup_push(cleanup, NULL);
  if (disabled && pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL)) atomic_store(&error, 3);
  atomic_store_explicit(&ready, 1, memory_order_release);
  struct timespec duration = {100, 0}, remaining = {99, 99};
  errno = EDOM;
  result = clock_nanosleep(CLOCK_PROCESS_CPUTIME_ID, 0, &duration, &remaining);
  if (!disabled || result != EINTR || errno != EDOM || remaining.tv_sec <= 0) atomic_store(&error, 4);
  if (disabled) {
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)) atomic_store(&error, 5);
    pthread_testcancel();
  }
  atomic_store(&error, 6);
  pthread_cleanup_pop(1);
  return NULL;
}
static uint64_t find_private(void) {
  uint64_t result = 0;
  /* Generic native ABI: PROCESS_MAX_OBJECT_HANDLES=4096, READ|WAIT=17. */
  for (uint64_t label = 1; label <= 4096; ++label) {
    if (native(664, label, 0) != 17) continue;
    if (result) return UINT64_MAX;
    result = label;
  }
  return result;
}
int main(void) {
  main_thread = pthread_self();
  CHECK(sem_init(&gate, 0, 0) == 0);
  clockid_t own;
  CHECK(clock_getcpuclockid(0, &own) == 0);
  for (unsigned absolute = 0; absolute < 2; ++absolute) {
    pthread_t worker;
    CHECK(pthread_create(&worker, NULL, burn, NULL) == 0);
    uint64_t before = cpu();
    burn_deadline = before + 150000000;
    struct timespec request = timespec(absolute ? before + 50000000 : 50000000);
    struct timespec remaining = {99, 99};
    CHECK(sem_post(&gate) == 0);
    errno = EDOM;
    CHECK(clock_nanosleep(absolute ? own : CLOCK_PROCESS_CPUTIME_ID,
                         absolute ? TIMER_ABSTIME : 0, &request, &remaining) == 0);
    CHECK(errno == EDOM && remaining.tv_sec == 99 && remaining.tv_nsec == 99);
    CHECK(cpu() >= before + 50000000);
    void *result = (void *)1;
    CHECK(pthread_join(worker, &result) == 0 && result == NULL);
  }
  CHECK(sem_destroy(&gate) == 0);
  fputs("cpu-sleep-libc: PASS relative and absolute process CPU sleeps and errno\n", stderr);

  struct sigaction action = {.sa_handler = handler, .sa_flags = SA_RESTART};
  CHECK(sigemptyset(&action.sa_mask) == 0);
  CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
  for (unsigned absolute = 0; absolute < 2; ++absolute) {
    pthread_t notifier;
    CHECK(pthread_create(&notifier, NULL, interrupt_sleep, NULL) == 0);
    struct timespec request = timespec(absolute ? cpu() + 5000000000 : 5000000000);
    struct timespec remaining = {99, 99};
    errno = EDOM;
    CHECK(clock_nanosleep(own, absolute ? TIMER_ABSTIME : 0, &request, &remaining) == EINTR);
    CHECK(errno == EDOM);
    CHECK(absolute ? remaining.tv_sec == 99 && remaining.tv_nsec == 99
                   : remaining.tv_sec >= 4 && remaining.tv_sec < 5);
    void *result = (void *)1;
    CHECK(pthread_join(notifier, &result) == 0 && result == NULL);
  }
  CHECK(caught == 2);
  fputs("cpu-sleep-libc: PASS SA_RESTART interruption and relative remainder\n", stderr);

  int finished[2], release[2];
  CHECK(pipe(finished) == 0 && pipe(release) == 0);
  pid_t subject = fork();
  CHECK(subject >= 0);
  if (!subject) {
    if (close(finished[0]) || close(release[1])) _exit(61);
    burn_until(cpu() + 200000000);
    char marker = 'R';
    if (write(finished[1], &marker, 1) != 1 || read(release[0], &marker, 1) != 1) _exit(62);
    _exit(marker == 'Q' ? 0 : 63);
  }
  CHECK(close(finished[1]) == 0 && close(release[0]) == 0);
  clockid_t foreign;
  CHECK(clock_getcpuclockid(subject, &foreign) == 0);
  struct timespec duration = {0, 50000000};
  errno = EDOM;
  CHECK(clock_nanosleep(foreign, 0, &duration, NULL) == 0 && errno == EDOM);
  char marker;
  CHECK(read(finished[0], &marker, 1) == 1 && marker == 'R');
  CHECK(write(release[1], "Q", 1) == 1);
  CHECK(close(finished[0]) == 0 && close(release[1]) == 0);
  int status;
  CHECK(waitpid(subject, &status, 0) == subject && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  fputs("cpu-sleep-libc: PASS selected foreign process CPU clock\n", stderr);

  for (unsigned disabled = 0; disabled < 2; ++disabled) {
    atomic_store(&ready, 0); atomic_store(&error, 0); atomic_store(&cleaned, 0);
    pthread_t worker;
    CHECK(pthread_create(&worker, NULL, cancel_sleep, (void *)(uintptr_t)disabled) == 0);
    while (!atomic_load_explicit(&ready, memory_order_acquire)) sched_yield();
    uint64_t label = 0, started = cpu();
    while (!(label = find_private())) {
      CHECK(!atomic_load(&error) && cpu() - started < 5000000000);
      sched_yield();
    }
    CHECK(label != UINT64_MAX);
    atomic_store(&private_label, label);
    for (unsigned round = 0; round < 3; ++round) {
      pid_t child = -1;
      for (unsigned attempt = 0; attempt < 100; ++attempt) {
        child = fork();
        if (child >= 0 || errno != EAGAIN) break;
        struct timespec pause = {0, 10000000};
        CHECK(nanosleep(&pause, NULL) == 0);
      }
      CHECK(child >= 0);
      /* Child bootstrap may reuse an omitted numeric slot for a new native
       * thread reference. It must not retain the private READ|WAIT channel. */
      if (!child) _exit(native(664, label, 0) != 17 && !atomic_load(&cleaned) ? 0 : 51);
      int status = 0;
      CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
      CHECK(native(664, label, 0) == 17 && !atomic_load(&cleaned));
    }
    CHECK(pthread_cancel(worker) == 0);
    if (disabled) CHECK(pthread_kill(worker, SIGUSR1) == 0);
    void *result = NULL;
    CHECK(pthread_join(worker, &result) == 0 && result == PTHREAD_CANCELED);
    CHECK(!atomic_load(&error) && atomic_load(&cleaned) == 1);
    CHECK(native(664, label, 0) < 0);
  }
  fputs("cpu-sleep-libc: PASS cancellation, disabled cancellation, cleanup ordering and six foreign-thread forks\n", stderr);
  return 0;
}
