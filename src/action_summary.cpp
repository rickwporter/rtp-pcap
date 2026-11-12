#include <arpa/inet.h> // for inet_ntoa()
#include <cstdio>
#include <netinet/in.h>

#include <pcap/pcap.h>

#include "action_summary.h"
#include "packet_utilities.h"
#include "rtp_utils.h"

using namespace std;

typedef std::map<uint32_t, uint32_t> map_count_t;
typedef map_count_t::iterator map_count_i;

void rtp_pcap_summary(const char *progname, pcap_t *pcap_file, const rtpmap_t &rtpmap, rtp_pcap_filter_t *filter) {
    map_count_t ssrcs;
    map_count_t codecs;
    map_count_i icount;
    uint32_t total_pkt_count = 0;
    uint32_t stream_pkt_count = 0;
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
    fprintf(stdout, "  SSRCs (%zu):\n", ssrcs.size());
    for (icount = ssrcs.begin(); icount != ssrcs.end(); icount++) {
        fprintf(stdout, "    0x%08x : %u\n", icount->first, icount->second);
    }

    fprintf(stdout, "  Payload types (%zu):\n", codecs.size());
    for (icount = codecs.begin(); icount != codecs.end(); icount++) {
        fprintf(stdout, "    %s (%u) : %u\n", rtp_pcap_rtpmap_get_string(rtpmap, icount->first), icount->first, icount->second);
    }
}
