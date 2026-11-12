#include <algorithm>
#include <arpa/inet.h> // for inet_network()
#include <cstdio>
#include <cstdlib>  // for atoi()
#include <cstring>  // for memset()
#include <ctype.h>  // for tolower()
#include <string.h> // for strstr()
#include <string>
#include <strings.h> // for strcasecmp()

#include "arguments.h"

using namespace std;

void rtp_pcap_rtpmap_init(rtpmap_t &map) {
    // initialize with the well-known codecs
    map[0] = "pcmu";
    map[3] = "gsm";
    map[4] = "g723";
    map[5] = "dvi4";
    map[6] = "dvi4";
    map[7] = "lpc";
    map[8] = "pcma";
    map[9] = "g722";
    map[10] = "l16";
    map[11] = "l16";
    map[12] = "qcelp";
    map[13] = "cn";
    map[14] = "mpa";
    map[15] = "g728";
    map[18] = "g729";
    map[25] = "celb";
    map[26] = "jpeg";
    map[28] = "nv";
    map[31] = "h261";
    map[32] = "mpv";
    map[33] = "mp2t";
    map[34] = "h263";
    map[72] = "rtcp";
    map[73] = "rtcp";
    map[74] = "rtcp";
    map[75] = "rtcp";
    map[76] = "rtcp";
    map[RTP_PTYPE_DTMF_DEFAULT] = "telephone-events";
}

const char *rtp_pcap_rtpmap_get_string(const rtpmap_t &map, uint8_t payload_type) {
    rtpmap_t::const_iterator iMap = map.find(payload_type);
    if (iMap != map.end()) {
        return iMap->second.c_str();
    }

    return "unknown";
}

void rtp_pcap_rtpmap_parse_arg(rtpmap_t &map, const char *arg) {
    if (arg == NULL) {
        return;
    }

    string astr(arg);
    size_t pos = 0;
    size_t pos1;

    while (string::npos != (pos1 = astr.find('=', pos))) {
        string ptstr = astr.substr(pos, pos1 - pos);
        uint8_t ptype = atoi(ptstr.c_str());

        size_t pos2 = astr.find(':', pos);
        if (pos2 == string::npos) {
            pos2 = astr.length();
        }

        string text = astr.substr(pos1 + 1, pos2 - pos1 - 1);
        map[ptype] = text;
        pos = pos2 + 1;
    }
}

time_display_t rtp_pcap_time_display_parse(const char *arg) {
    if (arg == NULL) {
        return tdisp_none;
    }

    string str(arg);
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);

    if (str.find("prev") != string::npos) {
        return tdisp_prevpacket;
    }
    if (str.find("capt") != string::npos) {
        return tdisp_startcapture;
    }
    if (str.find("time") != string::npos) {
        return tdisp_timeofday;
    }
    if (str.find("date") != string::npos) {
        return tdisp_date;
    }

    return tdisp_none;
}

static const ArgDefList common_options = {
    {ARG_FILE, AFMT_FILE, "PCAP file"},
    {ARG_FILTER, AFMT_FILTER, "Flag to filter on source/destination IP/UDP (default dst)"},
    {ARG_ADDR, AFMT_ADDR, "Source/destination IP address"},
    {ARG_PORT, AFMT_PORT, "Source/destination UDP port"},
    {ARG_MAP, AFMT_MAP, "RTP payload type to string values"},
};

ArgumentDefinition::ArgumentDefinition(const string &name, const string &format, const string &description)
    : name(name), format(format), description(description) {}

static void print_option(const ArgumentDefinition &option) {
    fprintf(stdout, HELP_FMT, option.name.c_str(), option.format.c_str(), option.description.c_str());
}

static void print_options(const ArgDefList &options) {
    for (ArgDefList::const_iterator it = options.begin(); it != options.end(); ++it) {
        print_option(*it);
    }
}

ArgParser::ArgParser(int argc, char **argv) : argc_(argc), argv_(argv), index_(1), current_(NULL), action_(NULL) {}

void ArgParser::skip_action(const char *action) { action_ = action; }

bool ArgParser::next() {
    while (index_ < argc_) {
        current_ = argv_[index_++];
        if (action_ != NULL && current_ != NULL && 0 == strcasecmp(current_, action_)) {
            continue;
        }
        return true;
    }

    current_ = NULL;
    return false;
}

const char *ArgParser::arg() const { return current_; }

bool ArgParser::is(const char *name) const { return current_ != NULL && name != NULL && 0 == strcasecmp(current_, name); }

bool ArgParser::is_help() const { return is(ARG_HELP) || is("help"); }

const char *ArgParser::value() {
    if (index_ >= argc_) {
        return NULL;
    }
    return argv_[index_++];
}

const char *ArgParser::require(const char *option, char *error, size_t error_size) {
    const char *next = value();
    if (next == NULL && error != NULL && error_size > 0) {
        snprintf(error, error_size, "missing value for %s", option);
    }
    return next;
}

CommonArgs::CommonArgs() : src_filter(false), is_help(true) { rtp_pcap_rtpmap_init(rtpmap); }

void CommonArgs::init_filter(rtp_pcap_filter_t &filter) const {
    memset(&filter, 0, sizeof(filter));
    if (src_filter) {
        filter.flags = FILTER_FLAG_SRC_FILTER;
        if (!addr.empty()) {
            filter.flags |= FILTER_FLAG_SADDR_SET;
            filter.saddr = inet_network(addr.c_str());
        }
        if (!port.empty()) {
            filter.flags |= FILTER_FLAG_SPORT_SET;
            filter.sport = atoi(port.c_str());
        }
    } else {
        filter.flags = FILTER_FLAG_DST_FILTER;
        if (!addr.empty()) {
            filter.flags |= FILTER_FLAG_DADDR_SET;
            filter.daddr = inet_network(addr.c_str());
        }
        if (!port.empty()) {
            filter.flags |= FILTER_FLAG_DPORT_SET;
            filter.dport = atoi(port.c_str());
        }
    }
}

bool rtp_pcap_arg_is_help(const char *arg) { return arg != NULL && (0 == strcasecmp(arg, ARG_HELP) || 0 == strcasecmp(arg, "help")); }

rtp_pcap_parse_result_t rtp_pcap_parse_common_arg(ArgParser &parser, CommonArgs &args, char *error, size_t error_size) {
    if (parser.is_help()) {
        args.is_help = true;
        return parse_help;
    }

    if (parser.is(ARG_FILE)) {
        const char *value = parser.require(ARG_FILE, error, error_size);
        if (value == NULL) {
            return parse_error;
        }
        args.filename = value;
        return parse_ok;
    }

    if (parser.is(ARG_FILTER)) {
        const char *value = parser.require(ARG_FILTER, error, error_size);
        if (value == NULL) {
            return parse_error;
        }
        if (NULL != strstr(value, "src")) {
            args.src_filter = true;
        }
        return parse_ok;
    }

    if (parser.is(ARG_ADDR)) {
        const char *value = parser.require(ARG_ADDR, error, error_size);
        if (value == NULL) {
            return parse_error;
        }
        args.addr = value;
        return parse_ok;
    }

    if (parser.is(ARG_PORT)) {
        const char *value = parser.require(ARG_PORT, error, error_size);
        if (value == NULL) {
            return parse_error;
        }
        args.port = value;
        return parse_ok;
    }

    if (parser.is(ARG_MAP)) {
        const char *value = parser.require(ARG_MAP, error, error_size);
        if (value == NULL) {
            return parse_error;
        }
        rtp_pcap_rtpmap_parse_arg(args.rtpmap, value);
        return parse_ok;
    }

    // this means free to parse as action specific value
    return parse_ignored;
}

std::string rtp_pcap_args_ready(const CommonArgs &args) {
    if (args.filename.empty()) {
        return "missing filename";
    }
    return "";
}

void rtp_pcap_action_usage(const char *progname, const char *action, const ArgDefList &options) {
    fprintf(stdout, "\n%s %s usage:\n\n", progname, action);
    fprintf(stdout, "  %s %s [arguments]\n\n", progname, action);
    fprintf(stdout, "  Arguments\n");

    print_options(common_options);
    print_options(options);
    print_option(ArgumentDefinition(ARG_HELP, "", "This message"));
    fprintf(stdout, "\n");
}
