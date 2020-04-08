
#include <stdint.h>
#include <stddef.h>

typedef void ockam_vault_t;

#define OCKAM_VAULT_SHA256_OUTPUT_SIZE 32

ockam_error_t ockam_vault_random_bytes_generate(ockam_vault_t* vault, uint8_t* buffer, size_t buffer_size);
ockam_error_t ockam_vault_sha256(ockam_vault_t* vault, uint8_t* input, size_t input_size, uint8_t* output);
ockam_error_t ockam_vault_cleanup(ockam_vault_t* vault);


ockam_error_t ockam_vault_random_bytes_generate(ockam_vault_t* vault, uint8_t* buffer, size_t buffer_size) {
    return 0;
}

ockam_error_t ockam_vault_cleanup(ockam_vault_t* vault) {
    return 0;
}

ockam_error_t ockam_vault_sha256(ockam_vault_t *vault, uint8_t *input, size_t input_size, uint8_t *output) {
    return 0;
}
