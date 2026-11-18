#include <arpa/inet.h> // for inet_ntoa()
#include <cstdio>
#include <netinet/in.h>

#include <CLI/CLI.hpp>
#include <memory>
#include <pcap/pcap.h>

#include "action_list.h"
#include "arguments.h"
#include "packet_utilities.h"
#include "rtp_utils.h"
#include "time_utilities.h"

using namespace std;

typedef std::map<uint32_t, uint32_t> map_count_t;
typedef map_count_t::iterator map_count_i;

typedef struct {
    uint32_t total;
    uint32_t start_index;
    struct timeval start_time;
    struct timeval end_time;
    map_count_t ssrcs;
    map_count_t codecs;
} stream_counts_t;

typedef map<uint16_t, stream_counts_t> port_counts_t;
typedef map<uint32_t, port_counts_t> address_counts_t;

static void print_stream_span(
    const char *indent, uint32_t start_index, const struct timeval *start_time, const struct timeval *end_time, time_display_t time_type,
    const struct timeval *capture_start
) {
    fprintf(stdout, "%sStart index: %u\n", indent, start_index);
    char time_buffer[64];
    if (rtp_pcap_format_start_time(time_type, time_buffer, sizeof(time_buffer), start_time, capture_start)) {
        fprintf(stdout, "%sStart time: %s\n", indent, time_buffer);
    }
    fprintf(stdout, "%sDuration: %0.3f seconds\n", indent, tv2seconds(end_time) - tv2seconds(start_time));
}

static void rtp_pcap_list(
    const char *progname, pcap_t *pcap_file, const RtpMap &rtpmap, rtp_pcap_filter_t *filter, bool odd, bool all_udp, time_display_t time_type
) {
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

        stream_counts_t &stream = counts[packet.iph->daddr][packet.udph->dest];
        if (stream.total == 0) {
            stream.start_index = total_pkt_count;
            stream.start_time = packet.pcap_hdr.ts;
        }
        stream.end_time = packet.pcap_hdr.ts;
        stream.total += 1;
        if (RFC_1889_VERSION == rtp_hdr_get_version(rtph)) {
            stream.codecs[rtp_hdr_get_ptype(rtph)] += 1;
            stream.ssrcs[rtp_hdr_get_ssrc(rtph)] += 1;
        }
    } while (1);

    fprintf(stdout, "\n%s found (%u total packet in capture):\n", progname, total_pkt_count);
    for (address_counts_t::iterator iaddr = counts.begin(); iaddr != counts.end(); iaddr++) {
        addr.s_addr = htonl(iaddr->first);
        port_counts_t &ports = iaddr->second;
        for (port_counts_t::iterator iport = ports.begin(); iport != ports.end(); iport++) {
            stream_counts_t &stream = iport->second;
            fprintf(stdout, "  IP destination: %s:%d (%u packets)\n", inet_ntoa(addr), iport->first, stream.total);
            print_stream_span("    ", stream.start_index, &stream.start_time, &stream.end_time, time_type, &filter->capture_start);
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

struct ListArgs {
    CommonArgs common;
    bool odd;
    bool all_udp;
    string time;

    ListArgs() : odd(false), all_udp(false), time("capture") {}
};

static int run_list(const char *progname, ListArgs &args) {
    RtpMap rtpmap = args.common.create_rtpmap();

    pcap_t *pcap_file = rtp_pcap_open_input(progname, args.common.filename.c_str());
    if (NULL == pcap_file) {
        return -2;
    }

    rtp_pcap_filter_t filter;
    args.common.init_filter(filter);
    rtp_pcap_list(progname, pcap_file, rtpmap, &filter, args.odd, args.all_udp, rtp_pcap_time_display_parse(args.time));
    pcap_close(pcap_file);
    return 0;
}

void add_list_command(CLI::App &parent, int &exit_code, const char *progname) {
    shared_ptr<ListArgs> args = make_shared<ListArgs>();
    CLI::App *subcmd = rtp_pcap_add_subcommand(parent, ARG_ACT_LIST, "List all RTP streams");
    rtp_pcap_add_common_options(subcmd, args->common);
    rtp_pcap_add_start_time_option(subcmd, args->time);
    subcmd->add_flag("--odd", args->odd, "Include odd # ports in list (default only considers even)");
    subcmd->add_flag("--all", args->all_udp, "Print all UDP packets (not just suspected RTP)");

    string program(progname);
    subcmd->callback([&exit_code, program, args]() { exit_code = run_list(program.c_str(), *args); });
}
