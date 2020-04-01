#include <stdint.h>
#include <string.h>
#include "ockam/error.h"
#include "codec_local.h"

/**
 * encode_payload_aead_aes_gcm
 * @param encoded [out] - encoded bytes
 * @param length [in] - [in]: size of 'encoded' buffer
 * @param tag [in] - tag
 * @param tag_size [in] - size of tag
 * @param encrypted_data [in] - encrypted data
 * @param encrypted_size [in] - size of encrypted_data
 * @return - success: encoded+(*length)
 *         - failure: 0.
 */
uint8_t *encode_payload_aead_aes_gcm(uint8_t *encoded, uint16_t length, uint8_t *tag, uint16_t tag_length,
    uint8_t *encrypted_data, uint16_t encrypted_length) {

  uint16_t packet_length = tag_length+encrypted_length;

  if (length < packet_length+sizeof(uint16_t)) encoded = 0;
  if (0 == tag) encoded = 0;
  if (0 == encoded) goto exit_block;

  encoded = encode_variable_length_encoded_u2le(encoded, packet_length);
  if (0 == encoded) goto exit_block;

  memcpy(encoded, encrypted_data, encrypted_length);
  encoded += encrypted_length;

  memcpy(encoded, tag, tag_length);
  encoded += tag_length;

exit_block:
  return encoded;
}

/**
 * decode_payload_aead_aes_gcm
 * @param encoded [in] - encoded buffer
 * @param tag [out] - tag buffer
 * @param tag_length [in] - tag buffer size
 * @param encrypted_data [out] - encrypted buffer
 * @param encrypted_length [in/out] - in: size of 'encrypted_data'/out: byetes written to 'encrypted_data'
 * @return
 */
uint8_t *decode_payload_aead_aes_gcm(uint8_t *encoded, uint8_t *tag, uint16_t tag_length,
    uint8_t *encrypted_data, uint16_t *encrypted_length) {

  uint16_t    _length = 0;
  uint16_t    _encrypted_length = 0;

  if (0 == tag) encoded = 0;
  if (tag_length < AEAD_AES_GCM_TAG_SIZE) encoded = 0;
  if (0 == encoded) goto exit_block;

  encoded = decode_variable_length_encoded_u2le(encoded, &_length);
  _encrypted_length = _length - AEAD_AES_GCM_TAG_SIZE;
  if(*encrypted_length < _encrypted_length) {
    encoded = 0;
    goto exit_block;
  }
  *encrypted_length = _encrypted_length;

  memcpy(encrypted_data, encoded, _encrypted_length);
  encoded += _encrypted_length;
  memcpy(tag, encoded, AEAD_AES_GCM_TAG_SIZE);
  encoded += AEAD_AES_GCM_TAG_SIZE;

exit_block:
  return encoded;
}