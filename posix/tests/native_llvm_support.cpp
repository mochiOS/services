// Exercise the real target LLVMSupport archive, not an emulation of its APIs.
#include "llvm/ADT/SmallString.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/Program.h"
#include "llvm/Support/raw_ostream.h"
#include <cstdio>
#include <cerrno>
#include <pwd.h>
#include <cstring>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
  std::fprintf(stderr, "llvm-support: FAIL line=%d: %s\n", __LINE__, #x); \
  return 1; } } while (0)

namespace {
struct Scratch {
  llvm::SmallString<128> path;
  ~Scratch() { if (!path.empty()) llvm::sys::fs::remove(path); }
};
}

extern "C" int mochi_llvm_support_probe() {
  namespace fs = llvm::sys::fs;
  char account_storage[2048], name_storage[2048];
  struct passwd account, named, *account_result = nullptr;
  errno = 71;
  CHECK(getpwuid_r(getuid(), &account, account_storage, sizeof(account_storage), &account_result) == 0);
  CHECK(account_result == &account && account.pw_uid == getuid() && account.pw_dir[0] == '/' && errno == 71);
  CHECK(!std::strcmp(account.pw_passwd, "x"));
  CHECK(getpwnam_r(account.pw_name, &named, name_storage, sizeof(name_storage), &account_result) == 0);
  CHECK(account_result == &named && named.pw_uid == account.pw_uid && !std::strcmp(named.pw_dir, account.pw_dir));
  CHECK(getpwnam_r("nonexistent-account-226", &named, name_storage, sizeof(name_storage), &account_result) == 0 && !account_result);
  CHECK(getpwuid_r(getuid(), &named, name_storage, 1, &account_result) == ERANGE && !account_result);
  CHECK(getpwuid_r(getuid(), &named, reinterpret_cast<char *>(1), sizeof(name_storage), &account_result) == EFAULT && !account_result);
  llvm::SmallString<128> home;
  CHECK(llvm::sys::path::home_directory(home) && home == account.pw_dir);
  std::puts("passwd: PASS real account UID/name lookup caller storage range fault and missing record");
  Scratch data, replacement;
  int fd;
  CHECK(!fs::createTemporaryFile("llvm-support", "data", fd, data.path));
  std::string text(8192, 'x');
  text.replace(4096, 3, "RAM");
  {
    llvm::raw_fd_ostream output(fd, true);
    output << text;
    output.flush();
    CHECK(!output.has_error());
  }
  auto buffer = llvm::MemoryBuffer::getFile(data.path);
  CHECK(buffer && (*buffer)->getBuffer() == text);
  CHECK(!fs::openFileForRead(data.path, fd));
  {
    std::error_code error;
    fs::mapped_file_region mapping(fd, fs::mapped_file_region::readonly,
                                  4096, 4096, error);
    CHECK(!error && mapping.size() == 4096);
    CHECK(!std::memcmp(mapping.const_data(), "RAM", 3));
  }
  CHECK(::close(fd) == 0);
  CHECK(!fs::createTemporaryFile("llvm-support", "replace", fd, replacement.path));
  CHECK(::close(fd) == 0);
  CHECK(!fs::rename(data.path, replacement.path));
  CHECK(!fs::exists(data.path));
  buffer = llvm::MemoryBuffer::getFile(replacement.path);
  CHECK(buffer && (*buffer)->getBuffer() == text);

  const auto executable = fs::getMainExecutable("misleading-argv0", nullptr);
  CHECK(executable == "/system/bin/llvm-runtime-probe");
  const llvm::StringRef arguments[] = {"unrelated-child-argv0", "--llvm-support-child"};
  const std::optional<llvm::StringRef> redirects[] = {std::nullopt, data.path.str(), std::nullopt};
  std::string error;
  bool failed = true;
  std::optional<llvm::sys::ProcessStatistics> statistics;
  const int result = llvm::sys::ExecuteAndWait(executable, arguments, std::nullopt,
      redirects, 0, 0, &error, &failed, &statistics);
  if (result != 37 || failed || !error.empty())
    std::fprintf(stderr, "llvm-support: child result=%d failed=%d error=%s\n", result, failed, error.c_str());
  CHECK(result == 37 && !failed && error.empty());
  CHECK(statistics && statistics->PeakMemory > 0);
  CHECK(statistics->TotalTime >= statistics->UserTime);
  buffer = llvm::MemoryBuffer::getFile(data.path);
  CHECK(buffer && (*buffer)->getBuffer() == "llvm-support-child\n");
  std::puts("llvm-support: PASS real file buffer offset mmap rename spawn redirect wait4 statistics");
  return 0;
}
