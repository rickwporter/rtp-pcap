#pragma once

#include <pcap/pcap.h>
#include <stdint.h>

#include "arguments.h"
#include "ip_hdrs.h"
#include "rtp_types.h"

#define PKT_BUF_BYTES 2048
#define RTP_STATS_WINDOW_PACKETS 64

// #define DEBUG_PRINT(fmt, args...) fprintf(stderr, "%s: " fmt, __func__, ##args)
#define DEBUG_PRINT(fmt, args...)

typedef struct {
    struct pcap_pkthdr pcap_hdr;
    uint8_t buffer[PKT_BUF_BYTES];
    iphdr_t *iph;
    udphdr_t *udph;
    rtphdr_t *rtph;
} rtp_pcap_pkt_t;

void rtp_pcap_iph_byteswap(iphdr_t *iph);
void rtp_pcap_udph_byteswap(udphdr_t *udph);
int rtp_pcap_get_next_packet(pcap_t *pcap_file, uint32_t *total_packets, rtp_pcap_filter_t *filter, rtp_pcap_pkt_t *pkt);
