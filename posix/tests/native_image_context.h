/* User-space tests of opaque native context keys; the kernel knows no FD key
 * convention. Included after native_exec_address_space.c's CHECK and counters.
 */
static int64_t ei_context_native(uint64_t number, uint64_t a, uint64_t b,
                                 uint64_t c) {
  register uint64_t fourth __asm__("r10") = 0;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(a), "S"(b), "d"(c), "r"(fourth)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
#define EI_FD_HANDLE(fd) (UINT64_C(0x504f534800000000) | (uint32_t)(fd))
#define EI_FD_METADATA(fd) (UINT64_C(0x504f534600000000) | (uint32_t)(fd))
#define EI_OPAQUE_VALUE UINT64_C(0x696d675f63747831)
#define EI_OPAQUE_HANDLE UINT64_C(0x696d675f63747832)
#define EI_SENTINEL UINT64_C(0xfedcba9876543210)

static int ei_context_seed(int closed, uint64_t *reference) {
  int64_t memory = ei_context_native(671, 4096, 0, 0);
  CHECK(memory > 0);
  CHECK(ei_context_native(674, memory, (uintptr_t) "ctx", 3) == 3);
  uint64_t rights = UINT64_C(1) | (UINT64_C(1) << 63);
  int64_t readonly = ei_context_native(627, memory, rights, 0);
  CHECK(readonly > 0 && ei_context_native(626, memory, 0, 0) == 0);
  *reference = (uint64_t)readonly;
  CHECK(ei_context_native(648, EI_FD_HANDLE(closed), *reference, 0) == 0);
  CHECK(ei_context_native(648, EI_OPAQUE_HANDLE, *reference, 0) == 0);
  CHECK(ei_context_native(662, EI_FD_METADATA(closed), EI_SENTINEL, 0) == 0);
  CHECK(ei_context_native(662, EI_OPAQUE_VALUE, 987, 0) == 0);
  return 0;
}

static int ei_context_unchanged(int closed, uint64_t reference) {
  uint64_t value = 0;
  CHECK(ei_context_native(639, EI_FD_METADATA(closed), (uintptr_t)&value, 0) ==
            0 &&
        value == EI_SENTINEL);
  CHECK(ei_context_native(628, EI_FD_HANDLE(closed), 0, 0) ==
        (int64_t)reference);
  CHECK(ei_context_native(628, EI_OPAQUE_HANDLE, 0, 0) == (int64_t)reference);
  CHECK(ei_context_native(639, EI_OPAQUE_VALUE, (uintptr_t)&value, 0) == 0 &&
        value == 987);
  return 0;
}

static int ei_context_after_image(int closed) {
  uint64_t value = 0;
  CHECK(ei_context_native(639, EI_FD_METADATA(closed), (uintptr_t)&value, 0) ==
        -9);
  CHECK(ei_context_native(628, EI_FD_HANDLE(closed), 0, 0) == -9);
  CHECK(ei_context_native(639, EI_OPAQUE_VALUE, (uintptr_t)&value, 0) == 0 &&
        value == 987);
  int64_t reference = ei_context_native(628, EI_OPAQUE_HANDLE, 0, 0);
  CHECK(reference > 0);
  uint64_t rights = UINT64_C(1) | (UINT64_C(1) << 63);
  CHECK((uint64_t)ei_context_native(664, reference, 0, 0) == rights);
  char bytes[3];
  CHECK(ei_context_native(673, reference, (uintptr_t)bytes, 3) == 3 &&
        !memcmp(bytes, "ctx", 3));
  CHECK(ei_context_native(674, reference, (uintptr_t) "bad", 3) == -13);
  CHECK(ei_context_native(627, reference, 1, 0) == -13);
  CHECK(ei_context_native(626, reference, 0, 0) == 0);
  return 0;
}

static int ei_context_capacity_failure(int closed, uint64_t reference,
                                       char **arguments, char **environment) {
  const uint64_t prefix = UINT64_C(0x696d675f66696c00);
  unsigned count;
  for (count = 0; count < 256; ++count) {
    int64_t result = ei_context_native(662, prefix + count, 500 + count, 0);
    if (result == -28)
      break;
    CHECK(result == 0);
  }
  CHECK(count > 0 && count < 256);
  uint64_t handles = ei_handles();
  errno = 0;
  CHECK(execve("/system/services/compositor.service", arguments, environment) ==
            -1 &&
        errno == ENOSPC);
  CHECK(ei_handles() == handles);
  CHECK(ei_context_unchanged(closed, reference) == 0);
  unsigned before = atomic_load_explicit(&ei_counter, memory_order_acquire);
  for (unsigned spin = 0;
       spin < 100000 &&
       atomic_load_explicit(&ei_counter, memory_order_acquire) == before;
       ++spin)
    sched_yield();
  CHECK(atomic_load_explicit(&ei_counter, memory_order_acquire) != before);
  for (unsigned index = 0; index < count; ++index) {
    uint64_t value = 0;
    CHECK(ei_context_native(639, prefix + index, (uintptr_t)&value, 0) == 0 &&
          value == 500 + index);
    CHECK(ei_context_native(663, prefix + index, 0, 0) == 0);
  }
  return 0;
}
