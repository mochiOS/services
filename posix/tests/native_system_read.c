#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
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
    size_t large_size = 16 * 1024 * 1024;
    char *large = malloc(large_size);
    if (!large || lseek(fd, 0, SEEK_SET) != 0) return 18;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return 19;
    length = read(fd, large, large_size);
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0) return 20;
    if (length != (ssize_t)large_size || memcmp(large, bulk, sizeof(bulk))) return 21;
    if (lseek(fd, 0, SEEK_CUR) != (off_t)large_size) return 22;
    long long large_ms = (long long)(end.tv_sec - start.tv_sec) * 1000
        + (end.tv_nsec - start.tv_nsec) / 1000000;
    if (large_ms < 0 || large_ms > UINT_MAX) return 23;
    fprintf(stderr, "system-read: single 16MiB read in %u ms\n", (unsigned)large_ms);
    free(large);
    off_t tail = lseek(fd, -123, SEEK_END);
    if (tail < 0 || read(fd, buffer, sizeof(buffer)) != 123) return 24;
    if (lseek(fd, 0, SEEK_CUR) != tail + 123 || read(fd, buffer, sizeof(buffer)) != 0) return 25;
    fprintf(stderr, "system-read: shared short read and EOF ok\n");
    if (close(fd) != 0) return 13;
    fprintf(stderr, "system-read: ok\n");
    return 0;
}
