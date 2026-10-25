// Real compiler -> object -> ELF -> execution. No host tools or shell fallback.
#include "llvm/ADT/SmallString.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/Program.h"
#include "llvm/Support/raw_ostream.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {
constexpr const char *root = "/system/tests/posix/llvm";

struct Scratch {
  llvm::SmallString<128> path;
  ~Scratch() {
    if (!path.empty()) {
      if (auto error = llvm::sys::fs::remove_directories(path, false))
        std::fprintf(stderr, "native-clang: cleanup failed: %s\n", error.message().c_str());
    }
  }
};

std::string under(llvm::StringRef base, llvm::StringRef name) {
  llvm::SmallString<128> path(base);
  llvm::sys::path::append(path, name);
  return path.str().str();
}

bool write(llvm::StringRef path, llvm::StringRef contents) {
  std::error_code error;
  llvm::raw_fd_ostream output(path, error);
  if (error) return false;
  output << contents;
  output.flush();
  return !output.has_error();
}

int execute(const std::vector<std::string> &arguments,
            const std::string &output, const std::string &diagnostics) {
  std::vector<llvm::StringRef> views(arguments.begin(), arguments.end());
  const std::optional<llvm::StringRef> redirects[] = {
      std::nullopt, output, diagnostics};
  bool failed = false;
  std::string error;
  const int status = llvm::sys::ExecuteAndWait(
      arguments.front(), views, std::nullopt, redirects, 0, 0, &error, &failed);
  if (failed || status < 0 || !error.empty()) {
    std::fprintf(stderr, "native-clang: %s status=%d failed=%d error=%s\n",
                 arguments.front().c_str(), status, failed, error.c_str());
    return -1;
  }
  return status;
}

void show(llvm::StringRef path) {
  if (auto buffer = llvm::MemoryBuffer::getFile(path))
    llvm::errs() << (*buffer)->getBuffer();
}
}

#define CHECK(x) do { if (!(x)) { \
  std::fprintf(stderr, "native-clang: FAIL line=%d: %s\n", __LINE__, #x); \
  show(diagnostics); return 1; } } while (0)

extern "C" int mochi_native_clang_pipeline_probe() {
  Scratch scratch;
  if (auto error = llvm::sys::fs::createUniqueDirectory("mochios-clang", scratch.path)) {
    std::fprintf(stderr, "native-clang: temporary directory: %s\n", error.message().c_str());
    return 1;
  }
  const auto diagnostics = under(scratch.path, "diagnostics.txt");
  const auto output = under(scratch.path, "stdout.txt");
  const auto source = under(scratch.path, "main.c");
  const auto invalid = under(scratch.path, "invalid.c");
  const auto object = under(scratch.path, "main.o");
  const auto bad_object = under(scratch.path, "invalid.o");
  const auto executable = under(scratch.path, "compiled-app");
  const auto compiler = under(root, "bin/clang");
  const auto linker = under(root, "bin/ld.lld");
  const auto sdk = under(root, "sdk");
  CHECK(execute({compiler, "--version"}, output, diagnostics) == 0);
  CHECK(execute({linker, "--version"}, output, diagnostics) == 0);
  CHECK(write(source, R"C(
#include <stdio.h>
#include <stdlib.h>
static _Thread_local volatile int initialized = 17;
static _Thread_local volatile int zeroed;
int main(int argc, char **argv) {
  if (argc != 2 || atoi(argv[1]) != 25 || initialized != 17 || zeroed != 0) return 90;
  initialized += argc;
  zeroed = 23;
  printf("native-clang-generated: tls=%d\n", initialized + zeroed);
  return 37;
}
)C"));
  CHECK(write(invalid, "int main(void) { this is invalid C; }\n"));
  std::vector<std::string> compile = {
      compiler, "--target=x86_64-unknown-none-elf", "--sysroot=" + under(sdk, "sysroot"), "-std=c11", "-O2",
      "-D__mochios__=1",
      "-fno-pie", "-mno-red-zone", "-nostdinc", "-isystem",
      under(sdk, "sysroot/include"), "-isystem", under(root, "resource/include"),
      "-resource-dir", under(root, "resource"),
      "-c", invalid, "-o", bad_object};
  CHECK(execute(compile, output, diagnostics) == 1);
  CHECK(!llvm::sys::fs::exists(bad_object));
  {
    auto buffer = llvm::MemoryBuffer::getFile(diagnostics);
    CHECK(buffer && (*buffer)->getBuffer().contains("error:"));
  }
  compile[compile.size() - 3] = source;
  compile.back() = object;
  CHECK(execute(compile, output, diagnostics) == 0);
  {
    auto buffer = llvm::MemoryBuffer::getFile(object);
    CHECK(buffer && (*buffer)->getBufferSize() >= 64);
    CHECK(!std::memcmp((*buffer)->getBufferStart(), "\177ELF", 4));
    CHECK(static_cast<unsigned char>((*buffer)->getBufferStart()[16]) == 1);
  }
  CHECK(execute({linker, "-static", "--no-pie", "-z", "noexecstack",
      "-T", under(sdk, "lib/linker.ld"), under(sdk, "lib/crt0.o"), object,
      "--start-group", under(sdk, "lib/libmochi_user_newlib_runtime.a"),
      under(sdk, "lib/newlib_reent.o"), under(sdk, "sysroot/lib/libc.a"),
      under(sdk, "sysroot/lib/libm.a"), under(sdk, "lib/libgcc.a"),
      "--end-group", "-o", executable}, output, diagnostics) == 0);
  CHECK(execute({executable, "25"}, output, diagnostics) == 37);
  auto buffer = llvm::MemoryBuffer::getFile(output);
  CHECK(buffer && (*buffer)->getBuffer() == "native-clang-generated: tls=42\n");
  std::puts("native-clang: PASS diagnostics C compilation object LLD ELF execution and compiler TLS");
  return 0;
}
