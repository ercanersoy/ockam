#include <stdint.h>
#include "ockam/error.h"

#define AEAD_AES_GCM_TAG_SIZE     16
#define KEY_CURVE_SIZE            32


typedef enum {
  kInvalidParams        = kOckamErrorCodec | 0x0001u,
  kBufferInsufficient   = kOckamErrorCodec | 0x0002u
} OckamCodecError;

typedef enum {
  kCurve25519                 = 1,
  kCurveP256CompressedY0      = 2,
  kCurveP256CompressedY1      = 3,
  kCurveP256Uncompressed      = 4
} CodecKeyCurve;

uint8_t *decode_variable_length_encoded_u2le(uint8_t *in, uint16_t *val);
uint8_t *encode_variable_length_encoded_u2le(uint8_t *out, uint16_t val);
uint8_t *encode_payload_aead_aes_gcm(uint8_t *encoded, uint16_t length, uint8_t *tag, uint16_t tag_length,
                                     uint8_t *encrypted_data, uint16_t encrypted_length);
uint8_t *decode_payload_aead_aes_gcm(uint8_t *encoded, uint8_t *tag, uint16_t tag_length,
                                     uint8_t *encrypted_data, uint16_t *encrypted_length);
uint8_t *encode_public_key(uint8_t *encoded, CodecKeyCurve type, uint8_t *x, uint8_t* y);
uint8_t *decode_public_key(uint8_t *encoded, CodecKeyCurve *type,  uint8_t *x, uint8_t* y);