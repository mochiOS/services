/* Syscall-free objects for exercising real relocated lifecycle arrays. */
extern void lifecycle_record(char);

#if defined(LIFECYCLE_LEAF)
#define INIT 'l'
#define FIRST '1'
#define SECOND '2'
#define FINI 'L'
#define UNDO_FIRST 'A'
#define UNDO_SECOND 'B'
int lifecycle_leaf(void) { return 1; }
void lifecycle_cross_init(void) { lifecycle_record('X'); }
#elif defined(LIFECYCLE_FIRST)
#define INIT 'f'
#define FIRST '3'
#define SECOND '4'
#define FINI 'F'
#define UNDO_FIRST 'C'
#define UNDO_SECOND 'D'
extern int lifecycle_leaf(void);
int lifecycle_first(void) { return lifecycle_leaf() + 1; }
#elif defined(LIFECYCLE_SECOND)
#define INIT 's'
#define FIRST '5'
#define SECOND '6'
#define FINI 'S'
#define UNDO_FIRST 'G'
#define UNDO_SECOND 'H'
extern int lifecycle_leaf(void);
extern int lifecycle_first(void);
int lifecycle_second(void) { return lifecycle_first() + lifecycle_leaf(); }
#elif defined(LIFECYCLE_ROOT)
#define INIT 'r'
#define FIRST '7'
#define SECOND '8'
#define FINI 'R'
#define UNDO_FIRST 'I'
#define UNDO_SECOND 'J'
unsigned long __mochios_lifecycle_v1(void) { return 1; }
char lifecycle_events[64];
unsigned long lifecycle_length;
void lifecycle_record(char event) {
  lifecycle_events[lifecycle_length++] = event;
}
static void preinitialize(void) { lifecycle_record('P'); }
__attribute__((used, section(".preinit_array"))) static void (
        *const preinitializer)(void) = preinitialize;
extern void lifecycle_cross_init(void);
__attribute__((used, section(".init_array.00150"))) static void (
        *const cross_initializer)(void) = lifecycle_cross_init;
extern int lifecycle_first(void);
extern int lifecycle_second(void);
int lifecycle_result(void) { return lifecycle_first() + lifecycle_second(); }
void _start(void) { lifecycle_record('M'); }
#ifdef LIFECYCLE_NATIVE
static int same(const char *expected) {
  unsigned long length = 0;
  for (; expected[length]; ++length)
    if (expected[length] != lifecycle_events[length])
      return 0;
  return length == lifecycle_length;
}
int lifecycle_native_main(void) {
  if (!same("Pl12f34s56r7X8"))
    return 1;
  lifecycle_record('M');
  return 0;
}
int lifecycle_native_fini_ok(void) {
  return same("Pl12f34s56r7X8MJIRHGSDCFBAL") ? 42 : 98;
}
__asm__(".pushsection .text.lifecycle_entry,\"ax\",@progbits\n"
        ".global lifecycle_entry\n"
        "lifecycle_entry:\n"
        "mov %rsp, %rdi\n"
        "and $-16, %rsp\n"
        "call lifecycle_test_start\n"
        "ud2\n"
        ".popsection\n");
#endif
#else
#error "select a fixture role"
#endif

void lifecycle_init(void) { lifecycle_record(INIT); }
void lifecycle_fini(void) { lifecycle_record(FINI); }
__attribute__((constructor(101))) static void initialize_first(void) {
  lifecycle_record(FIRST);
}
__attribute__((constructor(202))) static void initialize_second(void) {
  lifecycle_record(SECOND);
}
__attribute__((destructor(101))) static void finalize_first(void) {
  lifecycle_record(UNDO_FIRST);
}
__attribute__((destructor(202))) static void finalize_second(void) {
  lifecycle_record(UNDO_SECOND);
}
