/**
 * Duplicate definitions of standard code. It is duplicated here
 * to avoid issues with those definitions not being available on Mac.
 */
#pragma once

#include <stdint.h>

struct iphdr {
    uint8_t ihl : 4, version : 4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
    /* Options are not part of the basic struct and follow it in the packet
     * buffer
     */
};

struct udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};
