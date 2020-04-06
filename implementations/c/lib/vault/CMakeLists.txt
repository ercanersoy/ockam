# Top-level Vault
project(vault C)

message(STATUS "")
message(STATUS "---------------------- Vault ---------------------")

ockam_cc_library(
   NAME
     vault
   SRCS
     "vault.c"
   PUBLIC )

add_subdirectory(default)
#add_subdirectory(atecc508a)
#add_subdirectory(atecc608a)

if(${OCKAM_BUILD_TESTS})
  add_subdirectory(tests_suite)
  add_subdirectory(tests)
endif()

