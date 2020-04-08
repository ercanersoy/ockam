

#include <stdint.h>
#include <stddef.h>

typedef uint32_t ockam_error_t;

#define OCKAM_ERROR_NONE 0u

void ockam_error_to_string(ockam_error_t error, char* buffer, size_t buffer_size);
