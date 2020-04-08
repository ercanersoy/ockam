
#include <stdio.h>

void ockam_io_print_buffer(uint8_t* buffer, size_t buffer_size) {
  int i;
  for (i = 1; i <= buffer_size; i++) {
    printf("0x%02x ", *buffer++);
  }
  printf("\n");
}
