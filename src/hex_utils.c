#include <ctype.h>  /* for isxdigit(), isspace() */
#include <stdint.h> /* for uint8_t */
#include <stdio.h>  /* for print() */
#include <string.h> /* for strncmp(), strlen() */

#include "hex_utils.h"

static char g_hex_dump_buffer[DEFAULT_HEXDUMP_BUFFER_SIZE];
static char g_binary_to_hex_buffer[DEFAULT_HEXDUMP_BUFFER_SIZE];

const char *hexdump(void *data, int num_bytes) { return hexdump_r(data, num_bytes, g_hex_dump_buffer, sizeof(g_hex_dump_buffer)); }

const char *hexdump_r(void *data, int num_bytes, char *buffer, int buflen) {
    char hex_out[80];
    char alpha_out[80];
    char line[256];
    int32_t hex_index;   // Indexes the hex digits in "output"
    int32_t alpha_index; // Indexes the alpha characters in "output"
    int32_t i;           // Temporary storage
    uint32_t line_offset = 0;
    unsigned char *input = (unsigned char *)data;

    if (!data || !buffer)
        return NULL;

    memset(buffer, 0, buflen);

    // must have enough space for all the lines
    int32_t line_count = num_bytes / 16 + (num_bytes % 16 == 0 ? 0 : 1);
    if (line_count * 80 > buflen) {
        fprintf(stderr, "%s: must have at least %d-byte output buffer for %u bytes\n", __func__, line_count * 80, num_bytes);
        return NULL;
    }

    while (num_bytes > 0) {
        // print the offset
        memset(hex_out, 0, sizeof(hex_out));
        memset(alpha_out, 0, sizeof(alpha_out));

        hex_index = 0;
        alpha_index = 0;
        for (i = 1; (i <= 16) && (num_bytes > 0); ++i) {
            // Convert a byte to hex...
            hex_out[hex_index] = "0123456789ABCDEF"[*input / 16];
            hex_out[hex_index + 1] = "0123456789ABCDEF"[*input % 16];

            /* and translate it to alpha */
            alpha_out[alpha_index] = ((*input >= 0x20) && (*input < 0x7f)) ? *input : '.';
            ++input;
            --num_bytes;
            ++alpha_index;
            hex_index += 2;

            // Insert a blank every 5th byte
            if ((i % 4) == 0) {
                hex_out[hex_index] = ' ';
                hex_index++;
            }
        }

        snprintf(line, sizeof(line), "%08x: %-36s  %s\n", line_offset, hex_out, alpha_out);
        strcat(buffer, line);

        line_offset += 16;
    }

    return buffer;
}

/* NOTE: reads an ASCII character into a nibble -- must be a hex value */
uint8_t ascii_to_nibble(char value) {
    if (value >= '0' && value <= '9') {
        return (value - '0');
    }

    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }

    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }

    return 0;
}

/* Reads the 2 ASCII characters from text, and converts */
static uint8_t ascii_to_byte(const char *text) {
    uint8_t value = ascii_to_nibble(*text) << 4;
    value += ascii_to_nibble(*(text + 1));
    return value;
}

int hex_string_to_binary(uint8_t *output, const char *input) {
    const char *input_pos = input;
    const char *input_end = input + strlen(input);
    uint8_t *output_pos = output;

    // ignore the first couple characters, if "0x" -- should this be required??
    if (strncmp(input, "0x", 2) == 0) {
        input_pos += 2;
    }

    for (; input_pos < input_end; input_pos += 2) {
        // skip whitespace
        if (isspace(*input_pos)) {
            input_pos--; // subtract one space, so incrementing by 2 does not miss a char
            continue;
        }

        // if not a space AND not a hexidecimal digit, we're done
        if (!isxdigit(*input_pos) || !isxdigit(*(input_pos + 1))) {
            return -1;
        }

        *output_pos = ascii_to_byte(input_pos);
        output_pos++;
    }

    return (output_pos - output);
}

static uint8_t nibble_to_hex_char(uint8_t nibble) {
    static const char digits[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    return digits[nibble & 0xF];
}

char *binary_to_hex_string_r(char *buffer, const void *binary, unsigned length) {
    const uint8_t *bytes = (uint8_t *)binary;
    unsigned i;

    /* double length, since one octet takes two hex characters */
    length *= 2;

    for (i = 0; i < length; i += 2) {
        *(buffer + i) = nibble_to_hex_char(*bytes >> 4);
        *(buffer + i + 1) = nibble_to_hex_char(*bytes++ & 0xF);
    }

    *(buffer + i) = 0; /* null terminate string */
    return buffer;
}

char *binary_to_hex_string(const void *binary, unsigned length) {
    // FIXME: make sure buffer is big enough
    return binary_to_hex_string_r(g_binary_to_hex_buffer, binary, length);
}
