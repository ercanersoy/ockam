# Ockam Vault Test

project(test_vault C)

message(STATUS "")
message(STATUS "-------------------Test Vault --------------------")

ockam_cc_test(
   NAME
     tests
   SRCS
     "test_vault.c"
   INCLUDES
     "${OCKAM_C_ROOT_DIR}/lib/vault/default"
   DEPS 
     ockam::vault
     ockam::vault::default
     ockam::memory
   PUBLIC )
