# Ockam Vault Default Test

project(test_default C)

message(STATUS "")
message(STATUS "---------------Test Vault Default ----------------")

ockam_cc_test(
   NAME
     full 
   SRCS
     "test_default.c"
   INCLUDES
     "${OCKAM_C_ROOT_DIR}/lib/vault/default"
     "${OCKAM_C_ROOT_DIR}/lib/vault/tests_suite"
   DEPS 
     ockam::vault::tests_suite
     ockam::vault::default
     ockam::memory
   PUBLIC )
