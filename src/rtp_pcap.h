#pragma once
#include <map>
#include <srtp2/srtp.h>
#include <stdint.h>

#include "ip_hdrs.h"
#include "rtp_types.h"

using namespace std;

#define PKT_BUF_BYTES 2048

typedef struct {
    uint32_t flags;
    uint32_t saddr; // TODO: make it IPv6 friendly
    uint32_t daddr; // TODO: make it IPv6 friendly
    uint16_t sport;
    uint16_t dport;
} rtp_pcap_filter_t;

typedef std::map<uint32_t, uint32_t> map_count_t;
typedef map_count_t::iterator map_count_i;
typedef std::map<uint8_t, std::string> rtpmap_t;

typedef struct {
    uint32_t total;
    map_count_t ssrcs;
    map_count_t codecs;
} stream_counts_t;

typedef map<uint16_t, stream_counts_t> port_counts_t;
typedef map<uint32_t, port_counts_t> address_counts_t;

typedef struct {
    struct pcap_pkthdr pcap_hdr;
    uint8_t buffer[PKT_BUF_BYTES];
    iphdr_t *iph;
    udphdr_t *udph;
    rtphdr_t *rtph;
} rtp_pcap_pkt_t;

typedef enum {
    tdisp_none,
    tdisp_prevpacket,
    tdisp_startcapture,
    tdisp_timeofday,
    tdisp_date,
} time_display_t;

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

typedef struct {
    bool odd;
    bool all_udp;
} rtp_pcap_list_args_t;

typedef enum {
    cryptop_none,
    cryptop_encrypt,
    cryptop_decrypt,
} cryptop_t;

typedef enum {
    srtp_alg_none,
    srtp_alg_aes128_sha1_32bit,
    srtp_alg_aes128_sha1_80bit,
} srtp_algorithm_t;

typedef struct {
    cryptop_t op;
    srtp_algorithm_t alg;
    bool force;
    bool debug;
    std::string key;
    std::string outfile;
} rtp_pcap_srtp_args_t;
