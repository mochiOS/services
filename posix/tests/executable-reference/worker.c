#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <mochi/executable.h>
int main(int argc, char **argv) {
    const char text[] = MESSAGE;
    if (argc == 3 && strcmp(argv[1], "ipc") == 0) {
        int fd = atoi(argv[2]); char request[4];
        if (recv(fd, request, sizeof(request), 0) != 4 || memcmp(request, "host", 4)) return 8;
        return send(fd, text, sizeof(text) - 1, 0) == sizeof(text) - 1 ? 0 : 9;
    }
    int fd = argc > 1 ? atoi(argv[1]) : 1;
    return write(fd, text, sizeof(text) - 1) == sizeof(text) - 1 ? 0 : 7;
}
