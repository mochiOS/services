#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Native storage ABI; guarded by native_system_read_abi.rs. This test never
 * writes storage and obtains its sample range from the fixture's GPT. */
enum { BLOCK_READ = 555 };
static int block_read(uint64_t lba, void *bytes, size_t length) {
    uint64_t number = BLOCK_READ;
    register uint64_t r10 __asm__("r10") = length;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(0ULL), "S"(lba), "d"(bytes), "r"(r10)
                     : "rcx", "r11", "memory");
    return (int64_t)number == 0 ? 0 : -1;
}
static uint64_t little_u64(const unsigned char *bytes) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= (uint64_t)bytes[i] << (8 * i);
    return value;
}
static uint32_t little_u32(const unsigned char *bytes) {
    uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i) value |= (uint32_t)bytes[i] << (8 * i);
    return value;
}
static int measure_raw_sample(void) {
    static const unsigned char system_type[16] = {
        0x68,0x63,0x6f,0x6d,0x4f,0x69,0x00,0x53,0x80,0x00,0x6d,0x50,0x61,0x72,0x74,0x01
    };
    unsigned char header[512];
    size_t capacity = 256 * 1024;
    unsigned char *bytes = malloc(capacity);
    if (!bytes || block_read(1, header, sizeof(header))) return -1;
    if (memcmp(header, "EFI PART", 8)) return -1;
    uint64_t table = little_u64(header + 72);
    uint32_t count = little_u32(header + 80), size = little_u32(header + 84);
    if (!count || count > 128 || size != 128) return -1;
    size_t table_length = ((size_t)count * size + 511) & ~(size_t)511;
    if (block_read(table, bytes, table_length)) return -1;
    uint64_t first = 0, last = 0;
    for (uint32_t i = 0; i < count; ++i) {
        if (!memcmp(bytes + i * size, system_type, sizeof(system_type))) {
            if (first) return -1; /* This isolated fixture has one System. */
            first = little_u64(bytes + i * size + 32);
            last = little_u64(bytes + i * size + 40);
        }
    }
    if (!first || last < first || last - first < 32768) return -1;
    struct timespec start, end;
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return -1;
    for (uint64_t offset = 0; offset < 32768; offset += capacity / 512) {
        if (block_read(first + offset, bytes, capacity)) return -1;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &end)) return -1;
    long long elapsed_ms = (long long)(end.tv_sec - start.tv_sec) * 1000
        + (end.tv_nsec - start.tv_nsec) / 1000000;
    if (elapsed_ms < 0 || elapsed_ms > UINT_MAX) return -1;
    fprintf(stderr, "system-read: raw 16MiB in %u ms\n", (unsigned)elapsed_ms);
    free(bytes);
    return 0;
}

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
    if (measure_raw_sample()) return 26;
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
    /* Separate destination page population from the file/provider path without
     * changing the service-manager deadline. Reuse already resident storage. */
    if (lseek(fd, 0, SEEK_SET) != 0 || clock_gettime(CLOCK_MONOTONIC, &start)) return 27;
    length = read(fd, large, large_size / 2);
    if (clock_gettime(CLOCK_MONOTONIC, &end) || length != (ssize_t)(large_size / 2)) return 28;
    if (memcmp(large, bulk, sizeof(bulk))) return 29;
    long long resident_ms = (long long)(end.tv_sec - start.tv_sec) * 1000
        + (end.tv_nsec - start.tv_nsec) / 1000000;
    if (resident_ms < 0 || resident_ms > UINT_MAX) return 30;
    fprintf(stderr, "system-read: resident 8MiB read in %u ms\n", (unsigned)resident_ms);
    free(large);
    off_t tail = lseek(fd, -123, SEEK_END);
    if (tail < 0 || read(fd, buffer, sizeof(buffer)) != 123) return 24;
    if (lseek(fd, 0, SEEK_CUR) != tail + 123 || read(fd, buffer, sizeof(buffer)) != 0) return 25;
    fprintf(stderr, "system-read: shared short read and EOF ok\n");
    if (close(fd) != 0) return 13;
    fprintf(stderr, "system-read: ok\n");
    return 0;
}
