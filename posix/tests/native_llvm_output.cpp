// Exercise the actual output buffer used by LLD, including its commit path.
#include "llvm/Support/FileOutputBuffer.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>

namespace {
struct Scratch {
  llvm::SmallString<128> path;
  ~Scratch() { if (!path.empty()) llvm::sys::fs::remove(path); }
};
struct Descriptor {
  int value = -1;
  ~Descriptor() { if (value >= 0) ::close(value); }
};
}

#define CHECK(x) do { if (!(x)) { \
  std::fprintf(stderr, "llvm-output: FAIL line=%d: %s errno=%d\n", __LINE__, #x, errno); \
  return 1; } } while (0)

extern "C" int mochi_llvm_output_probe() {
  namespace fs = llvm::sys::fs;
  Scratch output;
  Descriptor old, writable;
  CHECK(!fs::createTemporaryFile("llvm-output", "elf", old.value, output.path));
  CHECK(::write(old.value, "old", 3) == 3);
  const std::string expected(8192, 'L');
  auto buffer = llvm::FileOutputBuffer::create(output.path, expected.size(),
                                              llvm::FileOutputBuffer::F_executable);
  if (!buffer) {
    llvm::logAllUnhandledErrors(buffer.takeError(), llvm::errs(), "llvm-output: create: ");
    return 1;
  }
  CHECK((*buffer)->getBufferSize() == expected.size());
  std::memcpy((*buffer)->getBufferStart(), expected.data(), expected.size());
  if (auto error = (*buffer)->commit()) {
    llvm::logAllUnhandledErrors(std::move(error), llvm::errs(), "llvm-output: commit: ");
    return 1;
  }
  auto contents = llvm::MemoryBuffer::getFile(output.path);
  CHECK(contents && (*contents)->getBuffer() == expected);
  auto permissions = fs::getPermissions(output.path);
  CHECK(permissions && ((*permissions & fs::owner_exe) != fs::no_perms));
  // Atomic replacement must preserve the old inode behind this open FD.
  char original[8] = {};
  CHECK(::pread(old.value, original, sizeof(original), 0) == 3);
  CHECK(!std::memcmp(original, "old", 3));

  // Do not accept FileOutputBuffer's anonymous-buffer fallback as evidence
  // that writable file mmap works: test that operation explicitly as well.
  writable.value = ::open(output.path.c_str(), O_RDWR);
  CHECK(writable.value >= 0);
  CHECK(::lseek(writable.value, 19, SEEK_SET) == 19);
  {
    std::error_code error;
    fs::mapped_file_region region(writable.value, fs::mapped_file_region::readwrite,
                                 4096, 4096, error);
    CHECK(!error && region.size() == 4096);
    std::memcpy(region.data(), "mapped", 6);
    // LLD's commit path relies on unmap; no explicit msync is used here.
    region.unmap();
  }
  CHECK(::lseek(writable.value, 0, SEEK_CUR) == 19);
  contents = llvm::MemoryBuffer::getFile(output.path);
  std::string updated = expected;
  updated.replace(4096, 6, "mapped");
  CHECK(contents && (*contents)->getBuffer() == updated);

  // Abandoning an output buffer must not replace the existing destination.
  {
    auto abandoned = llvm::FileOutputBuffer::create(output.path, 32);
    if (!abandoned) {
      llvm::logAllUnhandledErrors(abandoned.takeError(), llvm::errs(), "llvm-output: discard: ");
      return 1;
    }
    std::memset((*abandoned)->getBufferStart(), 'x', 32);
  }
  contents = llvm::MemoryBuffer::getFile(output.path);
  CHECK(contents && (*contents)->getBuffer() == updated);
  std::puts("llvm-output: PASS mapped output commit executable mode atomic replacement old FD offset writes and discard");
  return 0;
}
