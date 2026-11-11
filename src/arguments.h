#pragma once

#include <map>
#include <stdint.h>
#include <string>

#define FILTER_FLAG_SRC_FILTER (1 << 0)
#define FILTER_FLAG_DST_FILTER (1 << 1)
#define FILTER_FLAG_SADDR_SET (1 << 2)
#define FILTER_FLAG_DADDR_SET (1 << 3)
#define FILTER_FLAG_SPORT_SET (1 << 4)
#define FILTER_FLAG_DPORT_SET (1 << 5)

#define RTP_PTYPE_DTMF_DEFAULT 101

typedef struct {
    uint32_t flags;
    uint32_t saddr; // TODO: make it IPv6 friendly
    uint32_t daddr; // TODO: make it IPv6 friendly
    uint16_t sport;
    uint16_t dport;
} rtp_pcap_filter_t;

typedef std::map<uint8_t, std::string> rtpmap_t;

typedef enum {
    tdisp_none,
    tdisp_prevpacket,
    tdisp_startcapture,
    tdisp_timeofday,
    tdisp_date,
} time_display_t;

void rtp_pcap_rtpmap_init(rtpmap_t &map);
const char *rtp_pcap_rtpmap_get_string(const rtpmap_t &map, uint8_t payload_type);
void rtp_pcap_rtpmap_parse_arg(rtpmap_t &map, const char *arg);
time_display_t rtp_pcap_time_display_parse(const char *arg);
