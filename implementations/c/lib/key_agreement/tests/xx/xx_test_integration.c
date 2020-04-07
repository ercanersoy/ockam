
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "ockam/error.h"
#include "ockam/key_agreement.h"
#include "../../xx/xx_local.h"
#include "ockam/memory.h"
#include "ockam/syslog.h"
#include "ockam/transport.h"
#include "ockam/vault.h"
#include "../../../../vault/default/default.h"

const OckamMemory *memory = &ockam_memory_stdlib;
static uint8_t ephemeralKey[KEY_SIZE];
static uint8_t staticKey[KEY_SIZE];

#define ACK "ACK"
#define ACK_SIZE 3
#define OK "OK"
#define OK_SIZE 2

extern OckamTransport ockamPosixTcpTransport;

OckamVaultDefaultConfig default_cfg = {.features = OCKAM_VAULT_ALL, .ec = kOckamVaultEcCurve25519};

OckamError XXTestInitiator(int argc, char *argv[], const OckamVault *vault, void *vault_ctx, bool generate_keys);
OckamError EstablishInitiatorConnection(int argc, char *argv[], const OckamTransport *transport,
                                        OckamTransportCtx *transportCtx);
OckamError OckamErrorXXTestInitiatorPrologue(KeyEstablishmentXX *xx, bool generate_keys);
OckamError TestInitiatorHandshake(const OckamVault *vault, OckamVaultCtx *vaultCtx, const OckamTransport *transport,
                                  OckamTransportCtx transportCtx, KeyEstablishmentXX *xx, bool generate_keys);

void usage(const char* progname) {
  printf("%s [OPTIONS]\n\n", progname);
  printf("OPTIONS\n");
  printf("  -e <ephemeral key>\t\tbase16-encoded key to use as initiator ephemeral key\n");
  printf("  -s <static key>\t\tbase16-encoded key to use as initiator static key\n\n");
  printf("If one key is specified, both must be specified.\nIf neither are given, keys will be generated.\n");

  return;
}

int main(int argc, char *argv[]) {
  const OckamVault *vault = &ockam_vault_default;
  OckamError status = kErrorNone;
  void *vault_ctx = NULL;
  bool generate_keys = true;
  bool has_ephemeral, has_static = false;
  uint32_t keyBytes;

  int ch;
  while ((ch = getopt(argc, argv, "he:s:")) != -1) {
    switch (ch) {
      case 'h':
        usage(argv[0]);
        return 2;

      case 'e':
        generate_keys = false;
        has_ephemeral = true;
        string_to_hex(optarg, ephemeralKey, &keyBytes);
        if (keyBytes != KEY_SIZE) {
          log_error(status, "invalid ephemeral key, expected base-16 encoded, 32-byte string");
          return 2;
        }
        break;

      case 's':
        generate_keys = false;
        has_static = true;
        string_to_hex(optarg, staticKey, &keyBytes);
        if (keyBytes != KEY_SIZE) {
          log_error(status, "invalid static key, expected base-16 encoded, 32-byte string");
          return 2;
        }
        break;

      case '?':
        status = kOckamError;
        printf("unrecognized option '%c'\n\n", ch);
        usage(argv[0]);
        log_error(status, "invalid command-line arguments");
        return 2;

      default:
        break;
    }
  }

  if (!generate_keys && (!has_ephemeral || !has_static)) {
    status = kOckamError;
    usage(argv[0]);
    log_error(status, "must specify both ephemeral and static keys!");
    return 2;
  }

  // Initialize the vault
  memory->Create(0);
  status = vault->Create(&vault_ctx, &default_cfg, memory);
  if (status != kErrorNone) {
    log_error(status, "vault creation failed!");
    goto exit_block;
  }

  // Run test as initiator
  status = XXTestInitiator(argc, argv, vault, vault_ctx, generate_keys);
  if (0 != status) {
    log_error(kTestFailure, "initiator test failed!");
  }

exit_block:
  printf("Test ended with status %0.4x\n", status);
  return status;
}

OckamError XXTestInitiator(int argc, char *argv[], const OckamVault *vault, void *vault_ctx, bool generate_keys) {
  const OckamTransport *transport = &ockamPosixTcpTransport;

  OckamError status = kErrorNone;
  OckamTransportCtx transportCtx;
  KeyEstablishmentXX handshake;
  uint8_t sendBuffer[MAX_TRANSMIT_SIZE];
  uint8_t recv_buffer[MAX_TRANSMIT_SIZE];
  uint16_t bytesReceived = 0;
  uint16_t transmit_size = 0;
  uint8_t test[64];
  uint32_t test_bytes;
  uint8_t test_responder[64];

  /*-------------------------------------------------------------------------
   * Establish transport transportCtx with responder
   *-----------------------------------------------------------------------*/
  printf("Establishing connection...\n");
  status = EstablishInitiatorConnection(argc, argv, transport, &transportCtx);
  if (kErrorNone != status) {
    log_error(status, "Connection failed!");
    goto exit_block;
  }
  printf("OK\n");

  /*-------------------------------------------------------------------------
   * Secure the transportCtx
   *-----------------------------------------------------------------------*/
  printf("Initiating handshake...\n");
  status = TestInitiatorHandshake(vault, vault_ctx, transport, transportCtx, &handshake, generate_keys);
  if (kErrorNone != status) {
    printf("FAILED\n");
    log_error(status, "Handshake failed!");
    goto exit_block;
  }
  printf("OK\n");

  /*-------------------------------------------------------------------------
   * Receive the test message
   *-----------------------------------------------------------------------*/
  printf("Waiting for ACK message...");
  status = transport->Read(transportCtx, recv_buffer, sizeof(recv_buffer), &bytesReceived);
  if (kErrorNone != status) {
    printf("FAILED\n");
    log_error(status, "Receive failed!");
    goto exit_block;
  }
  printf("RECEIVED\n");

  /*-------------------------------------------------------------------------
   * Confirm the test message
   *-----------------------------------------------------------------------*/
  printf("Decrypting ACK message...");
  status = XXDecrypt(&handshake, test, ACK_SIZE, recv_buffer, bytesReceived, &test_bytes);
  if (kErrorNone != status) {
    printf("FAILED\n");
    log_error(status, "Decrypt failed!");
    goto exit_block;
  }
  printf("OK\n");

  printf("Verifying ACK message...");
  const char *ackBytes = ACK;
  if (0 != memcmp((void *)test, ackBytes, ACK_SIZE)) {
    status = kXXKeyAgreementTestFailed;
    printf("INVALID\n");
    log_error(status, "Expected ACK, but got different message");
    goto exit_block;
  }
  printf("OK\n");

  /*-------------------------------------------------------------------------
   * Make the test message
   *-----------------------------------------------------------------------*/
  printf("Encrypting OK message...");
  const char *okBytes = OK;
  status = XXEncrypt(&handshake, (uint8_t*)okBytes, OK_SIZE, sendBuffer, sizeof(sendBuffer), &transmit_size);
  if (kErrorNone != status) {
    printf("FAILED\n");
    log_error(status, "Encrypt failed!");
    goto exit_block;
  }

  /*-------------------------------------------------------------------------
   * Send the test message
   *-----------------------------------------------------------------------*/
  printf("Sending OK message...");
  printf("transmit_size: %d\n", transmit_size);
  status = transport->Write(transportCtx, sendBuffer, transmit_size);
  if (kErrorNone != status) {
    printf("FAILED\n");
    log_error(status, "Send failed!");
    goto exit_block;
  }
  printf("OK\n");

exit_block:
  if (NULL != transportCtx) transport->Destroy(transportCtx);
  return status;
}

OckamError EstablishInitiatorConnection(int argc, char *argv[], const OckamTransport *transport,
                                        OckamTransportCtx *transportCtx) {
  OckamError status = kErrorNone;
  OckamInternetAddress responder_address;
  OckamTransportConfig tcpConfig = {kBlocking};

  // Get the IP address of the responder
  status = GetIpInfo(argc, argv, &responder_address);
  if (kErrorNone != status) {
    log_error(status, "failed to get address info");
    goto exit_block;
  }

  // Initialize TCP transportCtx
  status = transport->Create(transportCtx, &tcpConfig);
  if (kErrorNone != status) {
    log_error(status, "failed transport->create");
    goto exit_block;
  }

  // Try to connect
  status = transport->Connect(*transportCtx, &responder_address);
  if (kErrorNone != status) {
    log_error(status, "connect failed");
    goto exit_block;
  }

exit_block:
  return status;
}

/**
 ********************************************************************************************************
 *                                          TestInitiatorHandshake ()
 ********************************************************************************************************
 *
 * Summary: Test the handshake process by starting with predefined static and
 *ephemeral keys (generated in the prologue) and verifying intermediate results
 *against test data along the way
 *
 * @param transportCtx [in] - initialized transport transportCtx
 * @param xx [in/out] - pointer to handshake structure
 * @return [out] - kErrorNone on success
 ********************************************************************************************************
 */

OckamError TestInitiatorHandshake(const OckamVault *vault, OckamVaultCtx *vaultCtx, const OckamTransport *transport,
                                  OckamTransportCtx transportCtx, KeyEstablishmentXX *xx, bool generate_keys) {
  OckamError status = kErrorNone;
  uint8_t sendBuffer[MAX_TRANSMIT_SIZE];
  uint8_t recv_buffer[MAX_TRANSMIT_SIZE];
  uint16_t bytesReceived = 0;
  uint16_t transmit_size = 0;
  uint8_t compare[1024];
  uint32_t compare_bytes;

  /* Initialize the KeyEstablishmentXX struct */
  memset(xx, 0, sizeof(*xx));
  OckamKeyInitializeXX(xx, vault, vaultCtx, transport, transportCtx);

  /* Prologue initializes keys and handshake parameters */
  printf("Performing prologue...\n");
  status = OckamErrorXXTestInitiatorPrologue(xx, generate_keys);
  if (status != kErrorNone) {
    log_error(status, "OckamErrorXXTestInitiatorPrologue failed!");
    goto exit_block;
  }

  // Step 1 generate message
  printf("Making M1...\n");
  status = XXInitiatorM1Make(xx, sendBuffer, MAX_TRANSMIT_SIZE, &transmit_size);
  if (kErrorNone != status) {
    log_error(status, "XXInitiatorM1Make failed!");
    goto exit_block;
  }

  // Step 1 send message
  printf("Sending M1..");
  status = xx->transport->Write(transportCtx, sendBuffer, transmit_size);
  if (kErrorNone != status) {
    printf("ERR\n");
    log_error(status, "Send failed!");
    goto exit_block;
  }
  printf("OK\n");

  // Msg 2 receive
  printf("Receiving M2..\n");
  status = xx->transport->Read(transportCtx, recv_buffer, sizeof(recv_buffer), &bytesReceived);
  if (kErrorNone != status) {
    printf("ERR\n");
    log_error(status, "Receive failed!");
    goto exit_block;
  }
  printf("OK\n");

  // Msg 2 process
  printf("Processing M2..\n");
  status = XXInitiatorM2Process(xx, recv_buffer, bytesReceived);
  if (kErrorNone != status) {
    log_error(status, "Processing failed!");
    goto exit_block;
  }
  print_uint8_str(xx->re, KEY_SIZE, "Remote Ephemeral Key");
  print_uint8_str(recv_buffer, 64, "M2");
  if(0 != memcmp(xx->re, recv_buffer, 32)) {
    printf("Unexpected remote ephemeral key\n");
  }

  // Msg 3 make
  printf("Making M3..\n");
  status = XXInitiatorM3Make(xx, sendBuffer, &transmit_size);
  if (kErrorNone != status) {
    log_error(status, "XXInitiatorM3Make failed!");
    goto exit_block;
  }

  // Msg 3 send
  printf("Sending M3..\n");
  status = xx->transport->Write(transportCtx, sendBuffer, transmit_size);
  if (kErrorNone != status) {
    log_error(status, "Send failed!");
    goto exit_block;
  }

  printf("Performing epilogue..\n");
  status = XXInitiatorEpilogue(xx);
  if (kErrorNone != status) {
    log_error(status, "Epilogue failed!");
    goto exit_block;
  }

exit_block:
  return status;
}

OckamError OckamErrorXXTestInitiatorPrologue(KeyEstablishmentXX *xx, bool generate_keys) {
  OckamError status = kOckamErrorNone;

  if (generate_keys) {
    status = KeyEstablishPrologueXX(xx);
    goto exit_block;
  }

  // 1. Pick a static 25519 keypair for this handshake and set it to s
  status = xx->vault->KeySetPrivate(xx->vault_ctx, kOckamVaultKeyStatic, staticKey, KEY_SIZE);
  if (kOckamErrorNone != status) {
    log_error(status, "failed to set provided static keypair");
    goto exit_block;
  }

  status = xx->vault->KeyGetPublic(xx->vault_ctx, kOckamVaultKeyStatic, xx->s, KEY_SIZE);
  if (kOckamErrorNone != status) {
    log_error(status, "failed to get provided static public key");
    goto exit_block;
  }

  // 2. Generate an ephemeral 25519 keypair for this handshake and set it to e
  status = xx->vault->KeySetPrivate(xx->vault_ctx, kOckamVaultKeyEphemeral, ephemeralKey, KEY_SIZE);
  if (kOckamErrorNone != status) {
    log_error(status, "failed to set provided ephemeral keypair");
    goto exit_block;
  }

  status = xx->vault->KeyGetPublic(xx->vault_ctx, kOckamVaultKeyEphemeral, xx->e, KEY_SIZE);
  if (kOckamErrorNone != status) {
    log_error(status, "failed to get provided ephemeral public key");
    goto exit_block;
  }

  // Nonce to 0, k to empty
  xx->nonce = 0;
  memset(xx->k, 0, sizeof(xx->k));

  // Initialize h to "Noise_XX_25519_AESGCM_SHA256" and set prologue to empty
  memset(&xx->h[0], 0, SHA256_SIZE);
  memcpy(&xx->h[0], PROTOCOL_NAME, PROTOCOL_NAME_SIZE);

  // Initialize ck
  memset(&xx->ck[0], 0, SHA256_SIZE);
  memcpy(&xx->ck[0], PROTOCOL_NAME, PROTOCOL_NAME_SIZE);

  // h = SHA256(h || prologue), prologue is empty
  mix_hash(xx, NULL, 0);

exit_block:
  return status;
}
