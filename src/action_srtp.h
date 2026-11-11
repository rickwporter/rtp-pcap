#pragma once

#include "rtp_pcap.h"

#if INCLUDE_SRTP
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

srtp_algorithm_t rtp_pcap_parse_srtp_alg(const char *algstr);
void rtp_pcap_srtp(const char *progname, pcap_t *input, rtp_pcap_filter_t *filter, rtp_pcap_srtp_args_t *args);
#endif // INCLUDE_SRTP
