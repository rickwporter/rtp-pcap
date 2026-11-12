#pragma once

#include <pcap/pcap.h>

#include "arguments.h"

typedef struct {
    bool odd;
    bool all_udp;
} rtp_pcap_list_args_t;

void rtp_pcap_list(const char *progname, pcap_t *pcap_file, const rtpmap_t &rtpmap, rtp_pcap_filter_t *filter, rtp_pcap_list_args_t *args);
