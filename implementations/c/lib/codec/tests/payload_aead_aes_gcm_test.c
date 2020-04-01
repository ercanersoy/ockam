#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <setjmp.h>
#include "ockam/error.h"
#include "cmocka.h"
#include "codec_tests.h"
#include "../codec_local.h"

#define MAX_PACKET_SIZE 0x7fffu
#define MAX_ENCRYPTED_SIZE MAX_PACKET_SIZE - AEAD_AES_GCM_TAG_SIZE - sizeof(uint16_t)

extern void print_uint8_str(uint8_t *p, uint16_t size, char *msg);

uint8_t *test_payload = NULL;
uint8_t *end_payload = NULL;
uint8_t *encoded_payload = NULL;

int _test_codec_payload_aead_aes_gcm_setup(void **state) {
  int status = 0;

  test_payload = malloc(0x7fff);
  if (NULL == test_payload) {
    status = kOckamError;
    goto exit_block;
  }

  end_payload = malloc(0x7fff);
  if (NULL == end_payload) {
    status = kOckamError;
    goto exit_block;
  }

  encoded_payload = malloc(0x7fff);
  if (NULL == encoded_payload) {
    status = kOckamError;
    goto exit_block;
  }

  for (int i = 0; i < MAX_PACKET_SIZE; ++i) {
    test_payload[i] = (uint8_t)i;
  }

exit_block:
  return status;
}

void _test_codec_payload_aead_aes_gcm(void **state) {
  uint8_t *out = 0;
  uint8_t *in = 0;
  uint16_t tag_offset = 0;
  uint16_t encrypted_length_in = 0;
  uint16_t encrypted_length_out = 0;

  for (uint16_t i = 0; i < MAX_ENCRYPTED_SIZE; ++i) {
    memset(end_payload, 0, MAX_PACKET_SIZE);

    tag_offset = i;
    out = encode_payload_aead_aes_gcm(encoded_payload, MAX_PACKET_SIZE, test_payload+tag_offset, AEAD_AES_GCM_TAG_SIZE,
                                      test_payload, i);
    if (i & 0x8000u) {
      assert_null(out);
    } else {
      encrypted_length_out = i;
      in = decode_payload_aead_aes_gcm(encoded_payload, end_payload+tag_offset, AEAD_AES_GCM_TAG_SIZE,
          end_payload, &encrypted_length_out);
      assert_int_equal(i, encrypted_length_out);
      assert_int_equal(0, memcmp(test_payload, end_payload, i + AEAD_AES_GCM_TAG_SIZE));
    }
  }
}

int _test_codec_payload_aead_aes_gcm_teardown(void **state) {
  if (0 != test_payload) free(test_payload);
  if (0 != end_payload) free(end_payload);
  if (0 != encoded_payload) free(encoded_payload);

  return 0;
}