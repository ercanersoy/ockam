#include <stdint.h>
#include <string.h>
#include "ockam/error.h"
#include "codec_local.h"

/**
 * encode_payload
 * @param encoded [out] - buffer for encoded bytes
 * @param length [in] - size of buffer
 * @param data [in] - data to encode
 * @param data_length [in] - bytes to encode
 * @return
 */
uint8_t *encode_payload(uint8_t *encoded, uint16_t length, uint8_t *data, uint16_t data_length) {

  if (length < data_length+sizeof(uint16_t)) encoded = 0;
  if (0 == encoded) goto exit_block;

  encoded = encode_variable_length_encoded_u2le(encoded, data_length);
  if (0 == encoded) goto exit_block;

  memcpy(encoded, data, data_length);
  encoded += data_length;

exit_block:
  return encoded;
}

/**
 * decode_payload
 * @param encoded [in] - encoded bytes
 * @param data [out] - decoded bytes
 * @param data_length [in/out] - in: size of data/out: bytes decoded
 * @return
 */
uint8_t *decode_payload(uint8_t *encoded, uint8_t *data, uint16_t *data_length) {

  uint16_t _length;

  if (0 == encoded) goto exit_block;

  encoded = decode_variable_length_encoded_u2le(encoded, &_length);
  if(*data_length < _length) {
    encoded = 0;
    goto exit_block;
  }
  *data_length = _length;

  memcpy(data, encoded, _length);
  encoded += _length;

  exit_block:
  return encoded;
}