// Link against target libc++, libc++abi and libunwind, never host libraries.
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <regex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <sys/auxv.h>
#include <unistd.h>

#ifdef MOCHIOS_MEMORY_ADVICE_PROBE_218
extern "C" int mochi_memory_advice_probe(void);
#endif
#ifdef MOCHIOS_WAIT_USAGE_PROBE_222
extern "C" int mochi_wait_usage_probe(void);
#endif

#ifdef MOCHIOS_PUBLIC_ACCOUNT_PROBE_226
extern "C" int mochi_passwd_probe();
#endif

#ifdef MOCHIOS_LLVM_SUPPORT_PROBE_226
extern "C" int mochi_llvm_support_probe();
#endif

extern "C" int mochi_llvm_runtime_probe() {
#ifdef MOCHIOS_PUBLIC_ACCOUNT_PROBE_226
  if (mochi_passwd_probe()) return 26;
#endif
#ifdef MOCHIOS_LLVM_SUPPORT_PROBE_226
  if (mochi_llvm_support_probe()) return 26;
#endif
#ifdef MOCHIOS_WAIT_USAGE_PROBE_222
  if (mochi_wait_usage_probe()) return 22;
#endif
#ifdef MOCHIOS_MEMORY_ADVICE_PROBE_218
  if (mochi_memory_advice_probe()) return 18;
#endif
  const auto executable = reinterpret_cast<const char *>(getauxval(AT_EXECFN));
  if (!executable || std::strcmp(executable, "/system/bin/llvm-runtime-probe")) return 9;
  if (getauxval(AT_PAGESZ) != static_cast<unsigned long>(sysconf(_SC_PAGESIZE)) ||
      getauxval(AT_CLKTCK) != static_cast<unsigned long>(sysconf(_SC_CLK_TCK))) return 10;
  if (getauxval(AT_UID) != getuid() || getauxval(AT_EUID) != geteuid() ||
      getauxval(AT_GID) != getgid() || getauxval(AT_EGID) != getegid()) return 11;
  if (getauxval(AT_SECURE) != static_cast<unsigned long>(getuid() != geteuid() || getgid() != getegid())) return 12;
  errno = 123;
  if (getauxval(AT_BASE) != 0 || errno != 123) return 13;
  if (getauxval(~0UL) != 0 || errno != ENOENT) return 14;
  if (geteuid() == 0) {
    if (seteuid(501)) return 15;
    const bool retained = getauxval(AT_EUID) == 0 && geteuid() == 501;
    if (seteuid(0) || !retained) return 16;
  }
  std::vector<std::string> words{"clang", "LLVM", "lld"};
  std::sort(words.begin(), words.end());
  if (words.front() != "LLVM") return 1;
  if (!std::regex_match("clang18", std::regex("[[:alpha:]]+[[:digit:]]+"))) return 2;
  if (!std::regex_match(" ", std::regex("[[:blank:]]"))) return 3;
  if (std::regex_match("\n", std::regex("[[:print:]]"))) return 4;
  std::atomic<int> count{0};
  std::thread worker([&] { count.fetch_add(7); });
  worker.join();
  if (count.load() != 7) return 5;
  bool caught = false;
  try {
    throw std::runtime_error("native C++ unwind");
  } catch (const std::runtime_error &error) {
    caught = std::string(error.what()) == "native C++ unwind";
  }
  if (!caught) return 6;
  std::error_code error;
  auto cwd = std::filesystem::current_path(error);
  if (error || cwd.empty()) return 7;
  auto space = std::filesystem::space(cwd, error);
  if (error || space.capacity < space.available) return 8;
  std::puts("llvm-runtime: PASS vector string regex pthread exception filesystem");
  std::puts("auxiliary: PASS executable metadata identity secure clock and errno");
  return 0;
}

#ifdef MOCHIOS_LLVM_RUNTIME_STANDALONE
int main(int argc, char **argv) {
#ifdef MOCHIOS_LLVM_SUPPORT_PROBE_226
  if (argc == 2 && !std::strcmp(argv[1], "--llvm-support-child")) {
    std::puts("llvm-support-child");
    return 37;
  }
#endif
  return mochi_llvm_runtime_probe();
}
#endif
