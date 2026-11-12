#include <algorithm>
#include <cstdlib> // for atoi()
#include <ctype.h> // for tolower()
#include <string>

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
