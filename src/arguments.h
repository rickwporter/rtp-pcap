#pragma once

#include <stdint.h>

#include <map>
#include <string>
#include <vector>

#define FILTER_FLAG_SRC_FILTER (1 << 0)
#define FILTER_FLAG_DST_FILTER (1 << 1)
#define FILTER_FLAG_SADDR_SET (1 << 2)
#define FILTER_FLAG_DADDR_SET (1 << 3)
#define FILTER_FLAG_SPORT_SET (1 << 4)
#define FILTER_FLAG_DPORT_SET (1 << 5)

#define RTP_PTYPE_DTMF_DEFAULT 101

#define ARG_ACT_SUMMARY "summary"
#define ARG_ACT_DETAILS "details"
#define ARG_ACT_LIST "list"
#define ARG_ACT_ENCRYPT "encrypt"
#define ARG_ACT_DECRYPT "decrypt"
#define ARG_ACT_STATS "stats"

typedef struct {
    uint32_t flags;
    uint32_t saddr; // TODO: make it IPv6 friendly
    uint32_t daddr; // TODO: make it IPv6 friendly
    uint16_t sport;
    uint16_t dport;
} rtp_pcap_filter_t;

// Payload type to codec name. Unknown types report "unknown".
class RtpMap : public std::map<uint8_t, std::string> {
  public:
    RtpMap();

    void parse(const char *arg);
    const char *get_string(uint8_t payload_type) const;
};

typedef enum {
    tdisp_none,
    tdisp_prevpacket,
    tdisp_startcapture,
    tdisp_timeofday,
    tdisp_date,
} time_display_t;

// Values shared by every action. Address and port stay as text until the filter
// is initialized, so --filter and --ip/--port can be given in either order.
class CommonArgs {
  public:
    CommonArgs();

    RtpMap create_rtpmap() const;
    void init_filter(rtp_pcap_filter_t &filter) const;

    std::string filename;
    std::string filter; // "dst" or "src"
    std::string addr;
    std::string port;
    std::vector<std::string> rtpmap_values;
};

namespace CLI {
class App;
}

// Subcommand with case-insensitive name and flag matching, including --help.
CLI::App *rtp_pcap_add_command(CLI::App &app, const std::string &name, const std::string &description);

// Options shared by every action. The PCAP path is a required positional.
// Keyword values (--filter) are case-insensitive.
// File names, addresses, and rtpmap text keep the case they were given.
void rtp_pcap_add_common_options(CLI::App *cmd, CommonArgs &args);

// --time on details and stats. The stored value is one of the canonical names.
void rtp_pcap_add_time_option(CLI::App *cmd, std::string &time, const std::string &default_value, const std::string &description);

time_display_t rtp_pcap_time_display_parse(const std::string &name);
