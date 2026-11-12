#include <arpa/inet.h> // for inet_ntoa()
#include <cstdio>
#include <netinet/in.h>

#include <pcap/pcap.h>

#include "action_list.h"
#include "arguments.h"
#include "packet_utilities.h"
#include "rtp_utils.h"

using namespace std;

#define ARG_ODD "--odd"
#define ARG_ALL "--all"

static const ArgDefList list_options = {
    {ARG_ODD, "", "Include odd # ports in list (default only considers even)"},
    {ARG_ALL, "", "Print all UDP packets (not just suspected RTP)"},
};

typedef std::map<uint32_t, uint32_t> map_count_t;
typedef map_count_t::iterator map_count_i;

typedef struct {
    uint32_t total;
    map_count_t ssrcs;
    map_count_t codecs;
} stream_counts_t;

typedef map<uint16_t, stream_counts_t> port_counts_t;
typedef map<uint32_t, port_counts_t> address_counts_t;

static void rtp_pcap_list(const char *progname, pcap_t *pcap_file, const RtpMap &rtpmap, rtp_pcap_filter_t *filter, bool odd, bool all_udp) {
    map_count_t ssrcs;
    map_count_t addrs;
    map_count_i icount;
    uint32_t total_pkt_count = 0;
    rtp_pcap_pkt_t packet;
    rtphdr_t *rtph;
    struct in_addr addr;
    address_counts_t counts;

    do {
        int result = rtp_pcap_get_next_packet(pcap_file, &total_pkt_count, filter, &packet);
        if (0 != result) {
            break;
        }

        // if not considering odd ports, move along if not a even port
        if (!odd) {
            // if filtering on source port, but not one specified
            if ((filter->flags & FILTER_FLAG_SRC_FILTER) && !(filter->flags & FILTER_FLAG_SPORT_SET) && (packet.udph->source & 0x1)) {
                DEBUG_PRINT("pkt[%u]: ignoring odd source port (%d)\n", total_pkt_count, packet.udph->source);
                continue;
            }
            if ((filter->flags & FILTER_FLAG_DST_FILTER) && !(filter->flags & FILTER_FLAG_DPORT_SET) && (packet.udph->dest & 0x1)) {
                DEBUG_PRINT("pkt[%u]: ignoring odd destination port (%d)\n", total_pkt_count, packet.udph->dest);
                continue;
            }
        }

        rtph = packet.rtph;
        // only track non-RTP when tracking all UDP
        if (!all_udp && RFC_1889_VERSION != rtp_hdr_get_version(rtph)) {
            continue;
        }

        counts[packet.iph->daddr][packet.udph->dest].total += 1;
        if (RFC_1889_VERSION == rtp_hdr_get_version(rtph)) {
            counts[packet.iph->daddr][packet.udph->dest].codecs[rtp_hdr_get_ptype(rtph)] += 1;
            counts[packet.iph->daddr][packet.udph->dest].ssrcs[rtp_hdr_get_ssrc(rtph)] += 1;
        }
    } while (1);

    fprintf(stdout, "\n%s found (%u total packet in capture):\n", progname, total_pkt_count);
    for (address_counts_t::iterator iaddr = counts.begin(); iaddr != counts.end(); iaddr++) {
        addr.s_addr = htonl(iaddr->first);
        port_counts_t &ports = iaddr->second;
        for (port_counts_t::iterator iport = ports.begin(); iport != ports.end(); iport++) {
            stream_counts_t &stream = iport->second;
            fprintf(stdout, "  IP destination: %s:%d (%u packets)\n", inet_ntoa(addr), iport->first, stream.total);
            fprintf(stdout, "    SSRCs (%zu):\n", stream.ssrcs.size());
            for (icount = stream.ssrcs.begin(); icount != stream.ssrcs.end(); icount++) {
                fprintf(stdout, "      0x%08x : %u\n", icount->first, icount->second);
            }

            fprintf(stdout, "    Payload types (%zu):\n", stream.codecs.size());
            for (icount = stream.codecs.begin(); icount != stream.codecs.end(); icount++) {
                fprintf(stdout, "      %s (%u) : %u\n", rtpmap.get_string(icount->first), icount->first, icount->second);
            }
        }
    }
}

static void usage(const char *progname) { rtp_pcap_action_usage(progname, ARG_ACT_LIST, list_options); }

int run_list(const char *progname, int argc, char *argv[]) {
    bool odd = false;
    bool all_udp = false;
    CommonArgs common;

    ArgParser parser(argc, argv);
    parser.skip_action(ARG_ACT_LIST);

    char error[256];
    error[0] = '\0';

    while (parser.next()) {
        common.is_help = false;
        rtp_pcap_parse_result_t parsed = rtp_pcap_parse_common_arg(parser, common, error, sizeof(error));
        if (parsed == parse_help) {
            break;
        }
        if (parsed == parse_error) {
            break;
        }
        if (parsed == parse_ok) {
            continue;
        }

        if (parser.is(ARG_ODD)) {
            odd = true;
        } else if (parser.is(ARG_ALL)) {
            all_udp = true;
        } else {
            snprintf(error, sizeof(error), "invalid argument '%s'", parser.arg());
            break;
        }
    }

    if (common.is_help) {
        usage(progname);
        return 0;
    }
    if (error[0] != '\0') {
        usage(progname);
        fprintf(stdout, "\n%s: %s\n", progname, error);
        return -1;
    }
    std::string ready_error = rtp_pcap_args_ready(common);
    if (!ready_error.empty()) {
        usage(progname);
        fprintf(stdout, "\n%s: %s\n", progname, ready_error.c_str());
        return -1;
    }

    pcap_t *pcap_file = rtp_pcap_open_input(progname, common.filename.c_str());
    if (NULL == pcap_file) {
        return -2;
    }

    rtp_pcap_filter_t filter;
    common.init_filter(filter);
    rtp_pcap_list(progname, pcap_file, common.rtpmap, &filter, odd, all_udp);
    pcap_close(pcap_file);
    return 0;
}
