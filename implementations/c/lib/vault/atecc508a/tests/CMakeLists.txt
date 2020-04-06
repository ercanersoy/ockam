# Ockam Vault BearSSL

project(test_atecc508a C)

message(STATUS "")
message(STATUS "----------------- Test ATECC508A -----------------")

ockam_cc_test(
   NAME
     full 
   SRCS
     "test_atecc508a.c"
   INCLUDES
     "${cryptoauthlib-git_SOURCE_DIR}/lib"
     "${OCKAM_C_ROOT_DIR}/lib/vault/tests_suite"
     "${OCKAM_C_ROOT_DIR}/lib/vault/atecc508a"
   DEPS 
     ockam::vault::tests_suite
     ockam::vault::default
     ockam::vault::atecc508a
     ockam::memory
   PUBLIC)
