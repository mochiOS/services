#define _GNU_SOURCE 1
#include <sys/auxv.h>
#include <sys/resource.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "elf-metadata: FAIL line=%d errno=%d: %s\n", __LINE__, errno, #x); \
  return 1; } } while (0)
static uint64_t word64(const unsigned char *p) { uint64_t v; memcpy(&v,p,8); return v; }
static unsigned word16(const unsigned char *p) { uint16_t v; memcpy(&v,p,2); return v; }
static uint32_t word32(const unsigned char *p) { uint32_t v; memcpy(&v,p,4); return v; }

int mochi_elf_metadata_probe(void) {
  const unsigned char *table = (const void *)getauxval(AT_PHDR);
  const size_t stride = getauxval(AT_PHENT), count = getauxval(AT_PHNUM);
  const char *executable = (const void *)getauxval(AT_EXECFN);
  CHECK(table && executable && stride >= 56 && count && count <= 32 && stride <= 128);
  unsigned char header[64], source[4096];
  int fd = open(executable, O_RDONLY);
  CHECK(fd >= 0 && pread(fd, header, sizeof(header), 0) == sizeof(header));
  CHECK(!memcmp(header, "\177ELF", 4));
  CHECK(stride == word16(header+54) && count == word16(header+56));
  const size_t length = stride * count;
  CHECK(length <= sizeof(source));
  CHECK(pread(fd, source, length, word64(header+32)) == length && close(fd) == 0);
  CHECK(!memcmp(table, source, length));
  CHECK(getauxval(AT_ENTRY) == word64(header+24));
  int inside = 0;
  for (size_t n = 0; n < count; ++n) {
    const unsigned char *entry = source+n*stride;
    if (word32(entry) == 1) {
      const uint64_t start=word64(entry+16), size=word64(entry+40);
      if ((uintptr_t)table >= start && (uintptr_t)table+length <= start+size) inside=1;
    }
  }
#ifdef MOCHIOS_ELF_METADATA_INLINE
  CHECK(inside);
#else
  CHECK(!inside);
#endif
  // Both the private copy and the in-LOAD table in these fixtures are read
  // only. A faultable C output must not alter their bytes.
  errno = 0;
  CHECK(getrusage(RUSAGE_SELF, (struct rusage *)(uintptr_t)table) == -1 && errno == EFAULT);
  CHECK(!memcmp(table, source, length));
  puts(inside ? "elf-metadata: PASS exact readable in-LOAD headers and protected bytes"
              : "elf-metadata: PASS exact readable private headers and protected bytes");
  return 0;
}
#ifdef MOCHIOS_ELF_METADATA_STANDALONE
int main(void) { return mochi_elf_metadata_probe(); }
#endif
