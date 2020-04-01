#include <stdint.h>
#include <string.h>
#include "ockam/error.h"
#include "codec_local.h"

uint8_t *encode_public_key(uint8_t *encoded, CodecKeyCurve type, uint8_t *x, uint8_t* y) {

  *encoded++ = (uint8_t)type;

  memcpy(encoded, x, KEY_CURVE_SIZE);
  encoded += KEY_CURVE_SIZE;

  if(kCurveP256Uncompressed == type) {
    memcpy(encoded, y, KEY_CURVE_SIZE);
    encoded += KEY_CURVE_SIZE;
  }

  return encoded;
}

uint8_t *decode_public_key(uint8_t *encoded, CodecKeyCurve *type,  uint8_t *x, uint8_t* y) {

  *type = *encoded++;

  memcpy(x, encoded, KEY_CURVE_SIZE);
  encoded += KEY_CURVE_SIZE;

  if(kCurveP256Uncompressed == *type) {
    memcpy(y, encoded, KEY_CURVE_SIZE);
    encoded += KEY_CURVE_SIZE;
  }

  return encoded;
}
