
#include "ockam/error.h"

#include "ockam/memory_allocator.h"
#include "ockam/memory_allocator/stdlib.h"

#include "ockam/vault.h"
#include "ockam/vault/default.h"

#include "ockam/io.h"
#include "ockam/io/stdio.h"

/* This example program shows how to instantiate the default
 * software implementation of Ockam Vault interface and use
 * it to compute a sha256 hash of a string. */
int main(void) {
  int exit_code = 0;
  ockam_error_t error;

  /* Before we initialize a vault, we need to first initialize a memory
   * allocator, in this example we're using an allocator based on stdlib
   * malloc/free. */
  ockam_memory_allocator_t *memory_allocator = 0;
  error = ockam_memory_allocator_stdlib_initialize(&memory_allocator);
  if (error != OCKAM_ERROR_NONE) {
      goto exit;
  }

  /* Initialize the default software vault implementation. */
  ockam_vault_t *vault = 0;
  ockam_vault_default_options_t vault_options = {.memory_allocator = memory_allocator};
  error = ockam_vault_default_initialize(&vault, &vault_options);
  if (error != OCKAM_ERROR_NONE) {
      goto exit;
  }

  /* Calculate the sha256 hash of a fixed input */
  uint8_t input[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  uint8_t output[OCKAM_VAULT_SHA256_OUTPUT_SIZE] = {0};
  error = ockam_vault_sha256(vault, input, sizeof(input), &output[0]);
  if (error != OCKAM_ERROR_NONE) {
      goto exit;
  }

  /* Print the generated sha256 output. */
  ockam_io_print_buffer(&output[0], OCKAM_VAULT_SHA256_OUTPUT_SIZE);

exit:
  if (error != OCKAM_ERROR_NONE) {
      exit_code = -1;
  }

  ockam_vault_cleanup(vault);
  ockam_memory_allocator_cleanup(memory_allocator);

  return exit_code;
}
