/* Exercise retirement and the existing native launch/exec regression together. */
#define main socket_regression_main
#include "native_posix_socket_pair.c"
#undef main

int main(int argc, char **argv) {
  uint64_t result;
  register uint64_t fourth __asm__("r10") = 0;
  register uint64_t fifth __asm__("r8") = 0;
  register uint64_t sixth __asm__("r9") = 0;
  __asm__ volatile("syscall"
                   : "=a"(result)
                   : "a"(606), "D"(0), "S"(0), "d"(0),
                     "r"(fourth), "r"(fifth), "r"(sixth)
                   : "rcx", "r11", "memory");
  /* Raw native ABI errors are not newlib errno values (ENOSYS is 88 there). */
  if ((int64_t)result != -38) {
    fprintf(stderr, "native-manifest-launch-retired: FAIL raw=%lld\n",
            (long long)(int64_t)result);
    return 1;
  }
  puts("native-manifest-launch-retired: PASS");
  return socket_regression_main(argc, argv);
}
