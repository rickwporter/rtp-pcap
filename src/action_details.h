#pragma once

#include <pcap/pcap.h>

#include "arguments.h"

typedef enum {
    idisp_stream,
    idisp_pcap,
} index_display_t;

typedef struct {
    bool analyse;
    bool summarize;
    uint8_t dtmf_decode;
    time_display_t time_type;
    index_display_t index_type;
} rtp_pcap_details_args_t;

void rtp_pcap_details(const char *progname, pcap_t *pcap_file, const rtpmap_t &rtpmap, rtp_pcap_filter_t *filter, rtp_pcap_details_args_t *args);
