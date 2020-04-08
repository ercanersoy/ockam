
typedef void* ockam_memory_ctx_t;

typedef struct {
  ockam_error_t (*create)  (ockam_memory_ctx_t *p_ctx);
  ockam_error_t (*cleanup) (ockam_memory_ctx_t ctx);
  ockam_error_t (*alloc)   (ockam_memory_ctx_t ctx, uint8_t **buffer, size_t buffer_size);
} ockam_memory_impl, *ockam_memory_impl_t;

typedef struct {
  ockam_memory_impl_t impl;
  ockam_memory_ctx_t ctx;
} ockam_memory, *ockam_memory_t;

ockam_error_t ockam_memory_cleanup(ockam_memory_t memory);

ockam_error_t ockam_memory_cleanup(ockam_memory_t memory) {
  return 0;
}
