/* Run creation/update authority failures and FIFO ownership in one boot. */
#define MEMORY_ADMISSION_MAIN queued_admission_probe
#include "native_memory_admission.c"

int main(void) {
  int result = unused_memory_update_main();
  if (result != 0)
    return result;
  /* The first probe joined its provider and closed all of its references.
   * A new endpoint namespace must start with fresh test-provider contents. */
  atomic_store(&backing_handle, 0);
  atomic_store(&owner_endpoint, 0);
  stored_length = 8192;
  return queued_admission_probe();
}
