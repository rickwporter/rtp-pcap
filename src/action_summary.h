#pragma once

#include "rtp_pcap.h"

void rtp_pcap_summary(const char *progname, pcap_t *pcap_file, const rtpmap_t &rtpmap, rtp_pcap_filter_t *filter);
