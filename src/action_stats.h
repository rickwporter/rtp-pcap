#pragma once

#include "rtp_pcap.h"

typedef struct {
    time_display_t time_type;
} rtp_pcap_stats_args_t;

void rtp_pcap_stats(const char *progname, pcap_t *pcap_file, rtp_pcap_filter_t *filter, rtp_pcap_stats_args_t *args);
