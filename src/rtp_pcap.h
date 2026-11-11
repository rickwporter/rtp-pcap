#pragma once
#include <map>
#include <stdint.h>

#include "arguments.h"
#include "packet_utilities.h"
#include "rtp_types.h"

using namespace std;

#define RTP_STATS_WINDOW_PACKETS 64

typedef std::map<uint32_t, uint32_t> map_count_t;
typedef map_count_t::iterator map_count_i;

typedef struct {
    uint32_t total;
    map_count_t ssrcs;
    map_count_t codecs;
} stream_counts_t;

typedef map<uint16_t, stream_counts_t> port_counts_t;
typedef map<uint32_t, port_counts_t> address_counts_t;
