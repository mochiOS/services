#include <stdlib.h>
#include <string.h>

extern int exec_answer(void);
#ifndef ANSWER
#define ANSWER 42
#endif

int main(int argc, char **argv) {
    const char *environment = getenv("EXEC_TEST");
    return argc == 2 && !strcmp(argv[1], "kept") && environment &&
           !strcmp(environment, "kept") && exec_answer() == 42 ? ANSWER : 97;
}
