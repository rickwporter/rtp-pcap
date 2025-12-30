#include <ctype.h>  /* for isxdigit(), isspace() */
#include <stdint.h> /* for uint8_t */
#include <stdio.h>  /* for print() */
#include <string.h> /* for strncmp(), strlen() */

#include "hexutils.h"

static char g_hexDumpBuff[DEFAULT_HEXDUMP_BUFFER_SIZE];
static char bin2hex_buffer[DEFAULT_HEXDUMP_BUFFER_SIZE];

const char *hexdump(void *input, int nBytes) { return hexdump_r(input, nBytes, g_hexDumpBuff, sizeof(g_hexDumpBuff)); }

const char *hexdump_r(void *in, int nBytes, char *buffer, int bufsize) {
    char hexOut[80];
    char alphaOut[80];
    int32_t nHex;   // Indexes the hex digits in "output"
    int32_t nAlpha; // Indexes the alpha characters in "output"
    int32_t i;      // Temporary storage
    uint32_t lineOffset = 0;
    unsigned char *input = (unsigned char *)in;

    if (!in || !buffer)
        return NULL;

    memset(buffer, 0, bufsize);

    // must have enough space for all the lines
    int32_t nlines = nBytes / 16 + (nBytes % 16 == 0 ? 0 : 1);
    if (nlines * 80 > bufsize) {
        fprintf(stderr, "%s: must have at least %d-byte output buffer for %u bytes\n", __func__, nlines * 80, nBytes);
        return NULL;
    }

    while (nBytes > 0) {
        // print the offset
        memset(hexOut, 0, sizeof(hexOut));
        memset(alphaOut, 0, sizeof(alphaOut));

        nHex = 0;
        nAlpha = 0;
        for (i = 1; (i <= 16) && (nBytes > 0); ++i) {
            // Convert a byte to hex...
            hexOut[nHex] = "0123456789ABCDEF"[*input / 16];
            hexOut[nHex + 1] = "0123456789ABCDEF"[*input % 16];

            /* and translate it to alpha */
            alphaOut[nAlpha] = ((*input >= 0x20) && (*input < 0x7f)) ? *input : '.';
            ++input;
            --nBytes;
            ++nAlpha;
            nHex += 2;

            // Insert a blank every 5th byte
            if ((i % 4) == 0) {
                hexOut[nHex] = ' ';
                nHex++;
            }
        }

        // NOTE: this is "safe" because we already insured the buffer is big enough
        snprintf(buffer, bufsize, "%s%08x: %-36s  %s\n", buffer, lineOffset, hexOut, alphaOut);

        lineOffset += 16;
    }

    return buffer;
}

/* NOTE: reads an ASCII character into a nibble -- must be a hex value */
uint8_t ascii2nibble(char val) {
    if (val >= '0' && val <= '9') {
        return (val - '0');
    }

    if (val >= 'A' && val <= 'F') {
        return val - 'A' + 10;
    }

    if (val >= 'a' && val <= 'f') {
        return val - 'a' + 10;
    }

    return 0;
}

/* Reads the 2 ASCII characters from val, and converts */
uint8_t ascii2byte(const char *val) {
    uint8_t out = ascii2nibble(*val) << 4;
    out += ascii2nibble(*(val + 1));
    return out;
}

int hexString2Binary(uint8_t *output, const char *input) {
    const char *pIn = input;
    const char *pEnd = input + strlen(input);
    uint8_t *pOut = output;

    // ignore the first couple characters, if "0x" -- should this be required??
    if (strncmp(input, "0x", 2) == 0) {
        pIn += 2;
    }

    for (; pIn < pEnd; pIn += 2) {
        // skip whitespace
        if (isspace(*pIn)) {
            pIn--; // subtract one space, so incrementing by 2 does not miss a char
            continue;
        }

        // if not a space AND not a hexidecimal digit, we're done
        if (!isxdigit(*pIn) || !isxdigit(*(pIn + 1))) {
            return -1;
        }

        *pOut = ascii2byte(pIn);
        pOut++;
    }

    return (pOut - output);
}

uint8_t nibble2HexChar(uint8_t nibble) {
    static const char buf[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    return buf[nibble & 0xF];
}

char *bin2hexString_r(char *buffer, const void *bin, unsigned length) {
    const uint8_t *str = (uint8_t *)bin;
    unsigned i;

    /* double length, since one octet takes two hex characters */
    length *= 2;

    for (i = 0; i < length; i += 2) {
        *(buffer + i) = nibble2HexChar(*str >> 4);
        *(buffer + i + 1) = nibble2HexChar(*str++ & 0xF);
    }

    *(buffer + i) = 0; /* null terminate string */
    return buffer;
}

char *bin2hexString(const void *bin, unsigned length) {
    // FIXME: make sure buffer is big enough
    return bin2hexString_r(bin2hex_buffer, bin, length);
}
