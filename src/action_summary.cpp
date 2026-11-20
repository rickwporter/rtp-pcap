#include <arpa/inet.h> // for inet_ntoa()
#include <cstdio>
#include <netinet/in.h>

#include <CLI/CLI.hpp>
#include <memory>
#include <pcap/pcap.h>

#include "action_summary.h"
#include "arguments.h"
#include "packet_utilities.h"
#include "rtp_utils.h"
#include "time_utilities.h"

using namespace std;

typedef std::map<uint32_t, uint32_t> map_count_t;
typedef map_count_t::iterator map_count_i;

static void print_stream_span(
    const char *indent,
    uint32_t start_index,
    const struct timeval *start_time,
    const struct timeval *end_time,
    time_display_t time_type,
    const struct timeval *capture_start
) {
    fprintf(stdout, "%sStart index: %u\n", indent, start_index);
    char *formatted = rtp_pcap_format_start_time(time_type, start_time, capture_start);
    if (formatted != NULL) {
        fprintf(stdout, "%sStart time: %s\n", indent, formatted);
    }
    fprintf(stdout, "%sDuration: %0.3f seconds\n", indent, tv_to_seconds(end_time) - tv_to_seconds(start_time));
}

static void rtp_pcap_summary(const char *progname, pcap_t *pcap_file, const RtpMap &rtpmap, rtp_pcap_filter_t *filter, time_display_t time_type) {
    map_count_t ssrcs;
    map_count_t codecs;
    map_count_i icount;
    uint32_t total_pkt_count = 0;
    uint32_t stream_pkt_count = 0;
    uint32_t start_index = 0;
    struct timeval start_time = {};
    struct timeval end_time = {};
    rtp_pcap_pkt_t packet;
    rtphdr_t *rtph;
    struct in_addr addr;

    do {
        int result = rtp_pcap_get_next_packet(pcap_file, &total_pkt_count, filter, &packet);
        if (0 != result) {
            break;
        }

        rtph = packet.rtph;
        if (0 == stream_pkt_count && RFC_1889_VERSION != rtp_hdr_get_version(rtph)) {
            continue;
        }

        if (stream_pkt_count == 0) {
            start_index = total_pkt_count;
            start_time = packet.pcap_hdr.ts;
            if (filter->flags & FILTER_FLAG_DST_FILTER) {
                filter->flags |= FILTER_FLAG_DADDR_SET | FILTER_FLAG_DPORT_SET;
                filter->daddr = packet.iph->daddr;
                filter->dport = packet.udph->dest;
            } else if (filter->flags & FILTER_FLAG_SRC_FILTER) {
                filter->flags |= FILTER_FLAG_SADDR_SET | FILTER_FLAG_SPORT_SET;
                filter->saddr = packet.iph->saddr;
                filter->sport = packet.udph->source;
            }
        }

        end_time = packet.pcap_hdr.ts;
        stream_pkt_count++;
        ssrcs[rtp_hdr_get_ssrc(rtph)] += 1;
        codecs[rtp_hdr_get_ptype(rtph)] += 1;
    } while (1);

    addr.s_addr = htonl((filter->flags & FILTER_FLAG_DST_FILTER ? filter->daddr : filter->saddr));
    fprintf(stdout, "\n%s summary:\n", progname);
    fprintf(
        stdout,
        "  IP %s: %s:%d\n",
        filter->flags & FILTER_FLAG_DST_FILTER ? "destination" : "source",
        inet_ntoa(addr),
        filter->flags & FILTER_FLAG_DST_FILTER ? filter->dport : filter->sport
    );
    fprintf(stdout, "  RTP %u packets (%u in capture)\n", stream_pkt_count, total_pkt_count);
    if (stream_pkt_count > 0) {
        print_stream_span("  ", start_index, &start_time, &end_time, time_type, &filter->capture_start);
    }
    fprintf(stdout, "  SSRCs (%zu):\n", ssrcs.size());
    for (icount = ssrcs.begin(); icount != ssrcs.end(); icount++) {
        fprintf(stdout, "    0x%08x : %u\n", icount->first, icount->second);
    }

    fprintf(stdout, "  Payload types (%zu):\n", codecs.size());
    for (icount = codecs.begin(); icount != codecs.end(); icount++) {
        fprintf(stdout, "    %s (%u) : %u\n", rtpmap.get_string(icount->first), icount->first, icount->second);
    }
}

struct SummaryArgs {
    CommonArgs common;
    string time;

    SummaryArgs() : time("capture") {}
};

static int run_summary(const char *progname, SummaryArgs &args) {
    RtpMap rtpmap = args.common.create_rtpmap();

    pcap_t *pcap_file = rtp_pcap_open_input(progname, args.common.filename.c_str());
    if (NULL == pcap_file) {
        return -2;
    }

    rtp_pcap_filter_t filter;
    args.common.init_filter(filter);
    rtp_pcap_summary(progname, pcap_file, rtpmap, &filter, rtp_pcap_time_display_parse(args.time));
    pcap_close(pcap_file);
    return 0;
}

void add_summary_command(CLI::App &parent, int &exit_code, const char *progname) {
    shared_ptr<SummaryArgs> args = make_shared<SummaryArgs>();
    CLI::App *subcmd = rtp_pcap_add_subcommand(parent, ARG_ACT_SUMMARY, "Summarize the RTP stream");
    rtp_pcap_add_common_options(subcmd, args->common);
    rtp_pcap_add_start_time_option(subcmd, args->time);

    string program(progname);
    subcmd->callback([&exit_code, program, args]() { exit_code = run_summary(program.c_str(), *args); });
}
