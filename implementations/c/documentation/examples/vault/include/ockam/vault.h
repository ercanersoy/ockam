
#include <stdint.h>
#include <stddef.h>

#define OCKAM_VAULT_SHA256_OUTPUT_SIZE 32

typedef void* ockam_vault_ctx_t;

typedef struct {
  ockam_error_t (*create)  (ockam_vault_ctx_t *ctx, void *p_arg, const ockam_memory_t *memory);
  ockam_error_t (*cleanup) (ockam_vault_ctx_t ctx);
  ockam_error_t (*random)  (ockam_vault_ctx_t ctx, uint8_t *p_buffer, size_t buffer_size);
} ockam_vault_impl, *ockam_vault_impl_t;

typedef struct {
  ockam_vault_impl_t impl;
  ockam_vault_ctx_t ctx;
} ockam_vault, *ockam_vault_t;


ockam_error_t ockam_vault_random_bytes_generate(ockam_vault_t vault, uint8_t* buffer, size_t buffer_size);
ockam_error_t ockam_vault_sha256(ockam_vault_t vault, uint8_t* input, size_t input_size, uint8_t* output);
ockam_error_t ockam_vault_cleanup(ockam_vault_t vault);

ockam_error_t ockam_vault_random_bytes_generate(ockam_vault_t vault, uint8_t* buffer, size_t buffer_size) {
    return 0;
}

ockam_error_t ockam_vault_cleanup(ockam_vault_t vault) {
    return 0;
}

ockam_error_t ockam_vault_sha256(ockam_vault_t vault, uint8_t *input, size_t input_size, uint8_t *output) {
    return 0;
}
