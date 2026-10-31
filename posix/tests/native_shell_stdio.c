#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
  char cwd[256];
  if (argc != 2 || strcmp(argv[1], "shell-303") != 0 ||
      !getcwd(cwd, sizeof(cwd))) {
    return 1;
  }
  if (printf("shell-native-303: PASS uid=%lu cwd=%s argv=%s\n",
             (unsigned long)geteuid(), cwd, argv[1]) < 0) {
    return 2;
  }
  if (fprintf(stderr, "shell-native-303: stderr preserved\n") < 0) {
    return 3;
  }
  return 0;
}
