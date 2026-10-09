#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Isolated early-boot probe: intentionally exits instead of publishing input
 * readiness. It uses the service's inherited POSIX endpoint, not a fallback. */
int main(void) {
    fprintf(stderr, "system-read: start\n");
    int fd = open("/system/packages/binder/manifest.toml", O_RDONLY);
    if (fd < 0) { perror("system-read: manifest open"); return 1; }
    char manifest[4096];
    ssize_t length = read(fd, manifest, sizeof(manifest) - 1);
    if (length <= 0) return 2;
    manifest[length] = '\0';
    if (!strstr(manifest, "org.mochios.binder")) return 3;
    if (close(fd) != 0) return 4;
    if (chdir("/system") != 0) return 5;
    char cwd[256];
    if (!getcwd(cwd, sizeof(cwd)) || strcmp(cwd, "/system") != 0) return 6;
    if (chdir("..") != 0) return 7;
    if (!getcwd(cwd, sizeof(cwd)) || strcmp(cwd, "/") != 0) return 8;
    fprintf(stderr, "system-read: namespace ok\n");
    fd = open("/system/libraries/ime/ja.mime", O_RDONLY);
    if (fd < 0) { perror("system-read: dictionary open"); return 9; }
    char bulk[65536], inline_bytes[4088];
    length = read(fd, bulk, sizeof(bulk));
    if (length != sizeof(bulk) || lseek(fd, 0, SEEK_SET) != 0) return 15;
    size_t checked = 0;
    while (checked < sizeof(bulk)) {
        size_t count = sizeof(bulk) - checked;
        if (count > sizeof(inline_bytes)) count = sizeof(inline_bytes);
        length = read(fd, inline_bytes, count);
        if (length != (ssize_t)count || memcmp(inline_bytes, bulk + checked, count)) return 16;
        checked += count;
    }
    if (lseek(fd, 0, SEEK_SET) != 0) return 17;
    fprintf(stderr, "system-read: bulk matches inline bytes and shared offset\n");
    struct timespec start, end;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return 10;
    char buffer[65536];
    size_t total = 0;
    /* A 4MiB sample measures the real inherited-endpoint/Handle path without
     * loading or parsing the dictionary, or changing the boot deadline. */
    while (total < 4 * 1024 * 1024) {
        length = read(fd, buffer, sizeof(buffer));
        if (length <= 0) return 11;
        total += (size_t)length;
        if (total % (1024 * 1024) == 0) {
            if (clock_gettime(CLOCK_MONOTONIC, &end) != 0) return 12;
            long long elapsed_ms = (long long)(end.tv_sec - start.tv_sec) * 1000
                + (end.tv_nsec - start.tv_nsec) / 1000000;
            if (elapsed_ms < 0 || elapsed_ms > UINT_MAX) return 14;
            fprintf(stderr, "system-read: %u bytes in %u ms\n", (unsigned)total, (unsigned)elapsed_ms);
        }
    }
    if (close(fd) != 0) return 13;
    fprintf(stderr, "system-read: ok\n");
    return 0;
}
