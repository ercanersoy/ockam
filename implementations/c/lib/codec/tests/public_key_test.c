#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <setjmp.h>
#include "ockam/error.h"
#include "cmocka.h"
#include "codec_tests.h"
#include "../codec_local.h"

void _test_public_key(void **state) {
  uint8_t x_in[KEY_CURVE_SIZE];
  uint8_t y_in[KEY_CURVE_SIZE];
  uint8_t x_out[KEY_CURVE_SIZE];
  uint8_t y_out[KEY_CURVE_SIZE];
  uint8_t encoded[2*KEY_CURVE_SIZE + 1];
  uint8_t *encoded_ptr = encoded;
  CodecKeyCurve type;

  memset(x_in, 'O', KEY_CURVE_SIZE);
  memset(y_in, 'K', KEY_CURVE_SIZE);

  encoded_ptr = encode_public_key(encoded, kCurve25519, x_in, 0);
  assert_ptr_equal(encoded_ptr, encoded+KEY_CURVE_SIZE+1);
  encoded_ptr = decode_public_key(encoded, &type, x_out, 0);
  assert_ptr_equal(encoded_ptr, encoded+KEY_CURVE_SIZE+1);
  assert_int_equal(type, kCurve25519);
  assert_int_equal(0, memcmp(x_in, x_out, KEY_CURVE_SIZE));

  memset(x_out, 0, KEY_CURVE_SIZE);

  encoded_ptr = encode_public_key(encoded, kCurveP256Uncompressed, x_in, y_in);
  assert_ptr_equal(encoded_ptr, encoded+(2*KEY_CURVE_SIZE)+1);
  encoded_ptr = decode_public_key(encoded, &type, x_out, y_out);
  assert_ptr_equal(encoded_ptr, encoded+(2*KEY_CURVE_SIZE)+1);
  assert_int_equal(type, kCurveP256Uncompressed);
  assert_int_equal(0, memcmp(x_in, x_out, KEY_CURVE_SIZE));
  assert_int_equal(0, memcmp(y_in, y_out, KEY_CURVE_SIZE));

}