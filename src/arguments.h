#pragma once

#include <stddef.h>
#include <stdint.h>

#include <list>
#include <map>
#include <string>

#define FILTER_FLAG_SRC_FILTER (1 << 0)
#define FILTER_FLAG_DST_FILTER (1 << 1)
#define FILTER_FLAG_SADDR_SET (1 << 2)
#define FILTER_FLAG_DADDR_SET (1 << 3)
#define FILTER_FLAG_SPORT_SET (1 << 4)
#define FILTER_FLAG_DPORT_SET (1 << 5)

#define RTP_PTYPE_DTMF_DEFAULT 101

#define ARG_HELP "--help"
#define ARG_FILE "--file"
#define ARG_ADDR "--ip"
#define ARG_PORT "--port"
#define ARG_FILTER "--filter"
#define ARG_MAP "--rtpmap"

#define ARG_ACT_SUMMARY "summary"
#define ARG_ACT_DETAILS "details"
#define ARG_ACT_LIST "list"
#define ARG_ACT_ENCRYPT "encrypt"
#define ARG_ACT_DECRYPT "decrypt"
#define ARG_ACT_STATS "stats"

#define AFMT_FILE "<file>"
#define AFMT_ADDR "<addr>"
#define AFMT_PORT "<num>"
#define AFMT_FILTER "<dst|src>"
#define AFMT_MAP "<num=string[:num=string[...]]>"

#define HELP_FMT "      %-7s %-8s: %s\n"

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

    void init_filter(rtp_pcap_filter_t &filter) const;

    std::string filename;
    std::string addr;
    std::string port;
    bool src_filter; // --filter src; otherwise destination
    RtpMap rtpmap;
    bool is_help; // --help was given, or the action has no other arguments
};

class ArgumentDefinition {
  public:
    ArgumentDefinition(const std::string &name, const std::string &format, const std::string &description);

    std::string name;
    std::string format;
    std::string description;
};

typedef std::list<ArgumentDefinition> ArgDefList;

typedef enum {
    parse_ignored,
    parse_ok,
    parse_help,
    parse_error,
} rtp_pcap_parse_result_t;

// Walks argv, skipping the program name and any occurrence of the action word.
class ArgParser {
  public:
    ArgParser(int argc, char **argv);

    void skip_action(const char *action);
    bool next();
    const char *arg() const;
    bool is(const char *name) const;
    bool is_help() const;

    // Next argv entry, or NULL when this was the last argument.
    const char *value();

    // Like value(), and writes a "missing value" error when it is absent.
    const char *require(const char *option, char *error, size_t error_size);

  private:
    int argc_;
    char **argv_;
    int index_;
    const char *current_;
    const char *action_;
};

void rtp_pcap_rtpmap_parse_arg(RtpMap &map, const char *arg);
time_display_t rtp_pcap_time_display_parse(const char *arg);

bool rtp_pcap_arg_is_help(const char *arg);
rtp_pcap_parse_result_t rtp_pcap_parse_common_arg(ArgParser &parser, CommonArgs &args, char *error, size_t error_size);

// Returns an error message when a required common argument is missing, otherwise an empty string.
std::string rtp_pcap_args_ready(const CommonArgs &args);

void rtp_pcap_action_usage(const char *progname, const char *action, const ArgDefList &options);
