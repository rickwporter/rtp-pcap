#pragma once

#include <stdint.h>

/* NOTE: for easer (eventual) integration with Cavium, stdint.h is NOT included here. */

#if defined(__cplusplus)
extern "C" {
#endif /* __cplusplus */

#define DEFAULT_HEXDUMP_BUFFER_SIZE 2048

/**
 * These utilities print hexadecimal values in a "classic" means with an offset.
 */
const char *hexdump(void *data, int num_bytes);
const char *hexdump_r(void *data, int num_bytes, char *buffer, int buflen);

/**
 * These utilities switch between binary and a string of hexadecimal characters.
 */
int hex_string_to_binary(uint8_t *output, const char *input);
char *binary_to_hex_string(const void *binary, unsigned length);
char *binary_to_hex_string_r(char *buffer, const void *binary, unsigned length);

/* Expose these for unit testing */
uint8_t ascii_to_nibble(char value);

#if defined(__cplusplus)
} /* extern "C" */
#endif /* __cplusplus */
