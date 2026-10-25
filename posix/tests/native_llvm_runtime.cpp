// Link against target libc++, libc++abi and libunwind, never host libraries.
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <filesystem>
#include <regex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

extern "C" int mochi_llvm_runtime_probe() {
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
  return 0;
}

#ifdef MOCHIOS_LLVM_RUNTIME_STANDALONE
int main() { return mochi_llvm_runtime_probe(); }
#endif
