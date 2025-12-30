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
const char *hexdump(void *input, int nBytes);
const char *hexdump_r(void *input, int nBytes, char *buffer, int bufsize);

/**
 * These utilities switch between binary and a string of hexadecimal characters.
 */
int hexString2Binary(uint8_t *output, const char *input);
char *bin2hexString(const void *bin, unsigned length);
char *bin2hexString_r(char *buffer, const void *bin, unsigned length);

/* Expose these for unit testing */
uint8_t ascii2nibble(char val);

#if defined(__cplusplus)
} /* extern "C" */
#endif /* __cplusplus */
