// Execute compiler-generated FS-relative loads, stores and TLS initialization.
#include <atomic>
#include <cstdio>
#include <cstdint>
#include <thread>
#include <sys/wait.h>
#include <unistd.h>

namespace {
thread_local volatile int initialized = 0x12345678;
alignas(8192) thread_local volatile unsigned char zeroed[8193];
std::atomic<int> destroyed{0};
struct Lifetime {
  int value = 91;
  ~Lifetime() { destroyed.fetch_add(1); }
};
thread_local Lifetime lifetime;
}

#define CHECK(x) do { if (!(x)) { \
  std::fprintf(stderr, "static-tls: FAIL line=%d: %s\n", __LINE__, #x); \
  return 1; } } while (0)

extern "C" int mochi_static_tls_probe() {
  CHECK(initialized == 0x12345678);
  CHECK(reinterpret_cast<std::uintptr_t>(&zeroed[0]) % 8192 == 0);
  for (auto value : zeroed) CHECK(value == 0);
  initialized = 43;
  zeroed[8192] = 7;
  std::atomic<int> arrived{0}, failures{0};
  const auto parent_address = reinterpret_cast<std::uintptr_t>(&initialized);
  auto worker = [&](int id) {
    if (initialized != 0x12345678 || zeroed[8192] != 0 || lifetime.value != 91 ||
        reinterpret_cast<std::uintptr_t>(&initialized) == parent_address ||
        reinterpret_cast<std::uintptr_t>(&zeroed[0]) % 8192) failures.fetch_add(1);
    initialized = id;
    zeroed[8192] = static_cast<unsigned char>(id);
    lifetime.value = id;
    arrived.fetch_add(1);
    while (arrived.load() != 2) std::this_thread::yield();
    for (int i = 0; i < 64; ++i) {
      std::this_thread::yield();
      if (initialized != id || zeroed[8192] != id || lifetime.value != id)
        failures.fetch_add(1);
    }
  };
  std::thread first(worker, 17), second(worker, 23);
  first.join();
  second.join();
  CHECK(failures.load() == 0 && destroyed.load() == 2);
  CHECK(initialized == 43 && zeroed[8192] == 7);
  for (int i = 0; i < 8; ++i) {
    std::thread reused([&] {
      if (initialized != 0x12345678 || zeroed[8192] != 0 || lifetime.value != 91)
        failures.fetch_add(1);
      initialized = 13;
      zeroed[8192] = 9;
    });
    reused.join();
  }
  CHECK(failures.load() == 0 && destroyed.load() == 10);
  const pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    if (initialized != 43 || zeroed[8192] != 7) _exit(90);
    initialized = 67;
    zeroed[8192] = 19;
    std::thread fresh([&] {
      if (initialized != 0x12345678 || zeroed[8192] != 0) failures.fetch_add(1);
    });
    fresh.join();
    _exit(initialized == 67 && zeroed[8192] == 19 && failures.load() == 0 ? 0 : 91);
  }
  int status = 0;
  CHECK(waitpid(child, &status, 0) == child && status == 0);
  CHECK(initialized == 43 && zeroed[8192] == 7);
  std::puts("static-tls: PASS template zero-fill alignment isolation reuse destructors fork");
  return 0;
}
