/* One real process exercises retry, protection/unmap and both user/kernel COW
 * writes. Reuse the authoritative native probes instead of duplicating them. */
#define main vm_retry_probe
#include "native_vm_fault_retry.c"
#undef main
#undef CHECK
#define main clone_probe
#include "native_clone_cow.c"
#undef main
#undef CHECK

int main(void) {
    int result = vm_retry_probe();
    return result ? result : clone_probe();
}
