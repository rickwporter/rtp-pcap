#include <arpa/inet.h> // for inet_network()
#include <cstdio>
#include <cstdlib> // for atoi()
#include <cstring> // for memset()

#include <CLI/CLI.hpp>

#include "arguments.h"

using namespace std;

RtpMap::RtpMap() {
    // initialize with the well-known codecs
    (*this)[0] = "pcmu";
    (*this)[3] = "gsm";
    (*this)[4] = "g723";
    (*this)[5] = "dvi4";
    (*this)[6] = "dvi4";
    (*this)[7] = "lpc";
    (*this)[8] = "pcma";
    (*this)[9] = "g722";
    (*this)[10] = "l16";
    (*this)[11] = "l16";
    (*this)[12] = "qcelp";
    (*this)[13] = "cn";
    (*this)[14] = "mpa";
    (*this)[15] = "g728";
    (*this)[18] = "g729";
    (*this)[25] = "celb";
    (*this)[26] = "jpeg";
    (*this)[28] = "nv";
    (*this)[31] = "h261";
    (*this)[32] = "mpv";
    (*this)[33] = "mp2t";
    (*this)[34] = "h263";
    (*this)[72] = "rtcp";
    (*this)[73] = "rtcp";
    (*this)[74] = "rtcp";
    (*this)[75] = "rtcp";
    (*this)[76] = "rtcp";
    (*this)[RTP_PTYPE_DTMF_DEFAULT] = "telephone-events";
}

const char *RtpMap::get_string(uint8_t payload_type) const {
    const_iterator iMap = find(payload_type);
    if (iMap != end()) {
        return iMap->second.c_str();
    }

    return "unknown";
}

void RtpMap::parse(const char *arg) {
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
        (*this)[ptype] = text;
        pos = pos2 + 1;
    }
}

time_display_t rtp_pcap_time_display_parse(const string &name) {
    if (name == "previous") {
        return tdisp_prevpacket;
    }
    if (name == "capture") {
        return tdisp_startcapture;
    }
    if (name == "timeofday") {
        return tdisp_timeofday;
    }
    if (name == "date") {
        return tdisp_date;
    }

    return tdisp_none;
}

CommonArgs::CommonArgs() : filter("dst") {}

RtpMap CommonArgs::create_rtpmap() const {
    RtpMap rtpmap;
    for (vector<string>::const_iterator it = rtpmap_values.begin(); it != rtpmap_values.end(); ++it) {
        rtpmap.parse(it->c_str());
    }
    return rtpmap;
}

void CommonArgs::init_filter(rtp_pcap_filter_t &out) const {
    memset(&out, 0, sizeof(out));
    if (filter == "src") {
        out.flags = FILTER_FLAG_SRC_FILTER;
        if (!addr.empty()) {
            out.flags |= FILTER_FLAG_SADDR_SET;
            out.saddr = inet_network(addr.c_str());
        }
        if (!port.empty()) {
            out.flags |= FILTER_FLAG_SPORT_SET;
            out.sport = atoi(port.c_str());
        }
    } else {
        out.flags = FILTER_FLAG_DST_FILTER;
        if (!addr.empty()) {
            out.flags |= FILTER_FLAG_DADDR_SET;
            out.daddr = inet_network(addr.c_str());
        }
        if (!port.empty()) {
            out.flags |= FILTER_FLAG_DPORT_SET;
            out.dport = atoi(port.c_str());
        }
    }
}

CLI::App *rtp_pcap_add_command(CLI::App &app, const string &name, const string &description) {
    CLI::App *cmd = app.add_subcommand(name, description);
    // Help is created before option defaults are copied, so set both again here.
    cmd->ignore_case();
    cmd->option_defaults()->ignore_case();
    cmd->set_help_flag("-h,--help", "Print this help message and exit");
    return cmd;
}

void rtp_pcap_add_common_options(CLI::App *cmd, CommonArgs &args) {
    cmd->add_option("file", args.filename, "PCAP file")->required();

    cmd->add_option("--filter", args.filter, "Flag to filter on source or destination IP/UDP (default dst)")
        ->default_val("dst")
        ->transform(CLI::IsMember({"dst", "src"}, CLI::ignore_case));

    cmd->add_option("--ip", args.addr, "Source or destination IP address")->type_name("addr");
    cmd->add_option("--port", args.port, "Source or destination UDP port")->type_name("num");

    // One value per occurrence. type_size keeps a following flag from being consumed as another value.
    cmd->add_option("--rtpmap", args.rtpmap_values, "RTP payload type to string values")
        ->type_name("num=string[:num=string[...]]")
        ->type_size(1)
        ->expected(1);
}

void rtp_pcap_add_time_option(CLI::App *cmd, string &time, const string &default_value, const string &description) {
    cmd->add_option("--time", time, description)
        ->default_val(default_value)
        ->transform(CLI::IsMember({"none", "previous", "capture", "timeofday", "date"}, CLI::ignore_case));
}
