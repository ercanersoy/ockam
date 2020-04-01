#include <stdint.h>
#include "ockam/error.h"

#define TAG_SIZE 16

typedef enum {
  kInvalidParams = kOckamErrorCodec | 0x0001u,
} OckamCodecError;

typedef enum {
  kCurve25519                 = 1,
  kCurveP256CompressedY0      = 2,
  kCurveP256CompressedY1      = 3,
  kCurveP256Uncompressed      = 4
} CodecKeyCurve;

#define KEY_CURVE_SIZE 32

typedef struct {
  uint16_t length;
  uint8_t tag[TAG_SIZE];
  uint8_t encrypted_data[];
} PayloadAeadAesGcm;

uint8_t *decode_variable_length_encoded_u2le(uint8_t *in, uint16_t *val);
uint8_t *encode_variable_length_encoded_u2le(uint8_t *out, uint16_t val);
uint8_t *encode_payload_aead_aes_gcm(uint8_t *out, PayloadAeadAesGcm *payload);
uint8_t *decode_payload_aead_aes_gcm(uint8_t *in, PayloadAeadAesGcm *payload);
uint8_t *encode_public_key(uint8_t *encoded, CodecKeyCurve type, uint8_t *x, uint8_t* y);
uint8_t *decode_public_key(uint8_t *encoded, CodecKeyCurve *type,  uint8_t *x, uint8_t* y);