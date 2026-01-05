#include <algorithm>
#include <arpa/inet.h> // for ntohs()
#include <ctime>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h> // for atoi()
#include <string.h> // for memset()
#include <string>
#include <strings.h> // for strcasecmp()
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <pcap/pcap.h>

#include "base64.h"
#include "hexutils.h"
#include "ip_hdrs.h"
#include "rtp_pcap.h"
#include "rtp_types.h"
#include "rtp_utils.h"

using namespace std;

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// Macros/constants
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// #define DEBUG_PRINT(fmt, args...) fprintf(stderr, "%s: " fmt, __func__, ##args)
#define DEBUG_PRINT(fmt, args...)

#define ARG_FILE "--file"
#define ARG_ADDR "--ip"
#define ARG_PORT "--port"
#define ARG_FILTER "--filter"
#define ARG_MAP "--rtpmap"
#define ARG_HELP "--help"
#define ARG_DTMF "--dtmf"
#define ARG_ALL "--all"
#define ARG_QUIET "--quiet"
#define ARG_INDEX "--index"
#define ARG_TIME "--time"
#define ARG_ODD "--odd"
#define ARG_ALG "--alg"
#define ARG_KEY "--key"
#define ARG_OUTPUT "--output"
#define ARG_FORCE "--force"
#define ARG_DEBUG "--debug"
#define ARG_ALG "--alg"
#define ARG_KEY "--key"
#define ARG_OUTPUT "--output"
#define ARG_FORCE "--force"
#define ARG_DEBUG "--debug"

#define AFMT_FILE "<file>"
#define AFMT_ADDR "<addr>"
#define AFMT_PORT "<num>"
#define AFMT_FILTER "<dst|src>"
#define AFMT_MAP "<num=string[:num=string[...]]>"
#define AFMT_HELP ""
#define AFMT_DTMF "<num>"
#define AFMT_ALL ""
#define AFMT_QUIET ""
#define AFMT_INDEX "<pcap|stream>"
#define AFMT_TIME "<none|previous|capture|timeofday|date>"
#define AFMT_ODD ""
#define AFMT_ALG "<aes128-sha1-32|aes128-sha1-80>"
#define AFMT_KEY "<hex|base64>"
#define AFMT_OUTPUT "<filename>"
#define AFMT_FORCE ""
#define AFMT_DEBUG ""

#define ARG_ACT_SUMMARY "summary"
#define ARG_ACT_DETAILS "details"
#define ARG_ACT_LIST "list"
#define ARG_ACT_ENCRYPT "encrypt"
#define ARG_ACT_DECRYPT "decrypt"

#define SECTION_FMT "  %-20s\n"
#define HELP_FMT "      %-7s %-8s: %s\n"
#define ACTION_FMT "    %10s : %s\n"

// safe way to get the next string based on i
#define NEXT_ARG(i, c, v) (i + 1 < c ? v[++i] : NULL)

#define RTP_STATS_WINDOW_PACKETS 64
#define RTP_PTYPE_DTMF_DEFAULT 101

#define FILTER_FLAG_SRC_FILTER (1 << 0)
#define FILTER_FLAG_DST_FILTER (1 << 1)
#define FILTER_FLAG_SADDR_SET (1 << 2)
#define FILTER_FLAG_DADDR_SET (1 << 3)
#define FILTER_FLAG_SPORT_SET (1 << 4)
#define FILTER_FLAG_DPORT_SET (1 << 5)

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// Declarations
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
void usage(const char *progname) {
    fprintf(stdout, "\n%s usage:\n\n", progname);
    fprintf(stdout, "  %s <action> %s %s [arguments]\n\n", progname, ARG_FILE, AFMT_FILE);
    fprintf(stdout, SECTION_FMT, "Actions");
    fprintf(stdout, ACTION_FMT, ARG_ACT_LIST, "List all RTP streams");
    fprintf(stdout, ACTION_FMT, ARG_ACT_SUMMARY, "Summarize the RTP stream");
    fprintf(stdout, ACTION_FMT, ARG_ACT_DETAILS, "Provide RTP packet details");
    fprintf(stdout, ACTION_FMT, ARG_ACT_ENCRYPT, "Encrypt single RTP stream to another PCAP");
    fprintf(stdout, ACTION_FMT, ARG_ACT_DECRYPT, "Decrypt single RTP stream to another PCAP");
    fprintf(stdout, "\n");
    fprintf(stdout, SECTION_FMT, "Common arguments");
    fprintf(stdout, HELP_FMT, ARG_FILE, AFMT_FILE, "PCAP file");
    fprintf(stdout, HELP_FMT, ARG_FILTER, AFMT_FILTER, "Flag to filter on source/destination IP/UDP (default dst)");
    fprintf(stdout, HELP_FMT, ARG_ADDR, AFMT_ADDR, "Source/destination IP address");
    fprintf(stdout, HELP_FMT, ARG_PORT, AFMT_PORT, "Source/destination UDP port");
    fprintf(stdout, HELP_FMT, ARG_MAP, AFMT_MAP, "RTP payload type to string values");
    fprintf(stdout, HELP_FMT, ARG_HELP, AFMT_HELP, "This message");
    fprintf(stdout, "\n");
    fprintf(stdout, SECTION_FMT, "list arguments");
    fprintf(stdout, HELP_FMT, ARG_ODD, AFMT_ODD, "Include odd # ports in list (default only considers even)");
    fprintf(stdout, HELP_FMT, ARG_ALL, AFMT_ALL, "Print all UDP packets (not just suspected RTP)");
    fprintf(stdout, "\n");
    fprintf(stdout, SECTION_FMT, "details arguments");
    fprintf(stdout, HELP_FMT, ARG_ALL, AFMT_ALL, "Print all packets in stream");
    fprintf(stdout, HELP_FMT, ARG_QUIET, AFMT_QUIET, "Do NOT provide analysis comments on stream");
    fprintf(stdout, HELP_FMT, ARG_INDEX, AFMT_INDEX, "Index type (default is stream)");
    fprintf(stdout, HELP_FMT, ARG_TIME, AFMT_TIME, "Time display format (default=none)");
    fprintf(stdout, HELP_FMT, ARG_DTMF, AFMT_DTMF, "RTP payload type for DTMF decodes (default=101)");
    fprintf(stdout, "\n");
    fprintf(stdout, SECTION_FMT, "SRTP encrypt/decrypt arguments");
    fprintf(stdout, HELP_FMT, ARG_ALG, AFMT_ALG, "Cryptographic algorithm suite (default=aes128-sha1-32)");
    fprintf(stdout, HELP_FMT, ARG_KEY, AFMT_KEY, "Master key in hexidecimal format");
    fprintf(stdout, HELP_FMT, ARG_OUTPUT, AFMT_OUTPUT, "Output filename (default=output.pcap)");
    fprintf(stdout, HELP_FMT, ARG_FORCE, AFMT_FORCE, "Overwrite existing output file");
    fprintf(stdout, HELP_FMT, ARG_DEBUG, AFMT_DEBUG, "Turn on libSRTP debug");
    fprintf(stdout, "\n");
}

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

index_display_t rtp_pcap_index_display_parse(const char *arg) {
    if (arg == NULL) {
        return idisp_stream;
    }

    string str(arg);
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);

    if (str.find("p") != string::npos) {
        return idisp_pcap;
    }

    return idisp_stream;
}

void rtp_pcap_iph_byteswap(iphdr_t *iph) {
    iph->tot_len = ntohs(iph->tot_len);
    iph->id = ntohs(iph->id);
    iph->frag_off = ntohs(iph->frag_off);
    iph->check = ntohs(iph->check);
    iph->saddr = ntohl(iph->saddr);
    iph->daddr = ntohl(iph->daddr);
}

void rtp_pcap_udph_byteswap(udphdr_t *udph) {
    udph->source = ntohs(udph->source);
    udph->dest = ntohs(udph->dest);
    udph->len = ntohs(udph->len);
    udph->check = ntohs(udph->check);
}

int rtp_pcap_get_next_packet(pcap_t *pcap_file, uint32_t *total_packets, rtp_pcap_filter_t *filter, rtp_pcap_pkt_t *pkt) {
    uint8_t data_buffer[PKT_BUF_BYTES];
    const unsigned char *pcap_data;
    struct pcap_pkthdr *pcap_header_ptr = NULL;
    iphdr_t *iph;
    udphdr_t *udph;
    uint16_t eth_type;
    uint16_t ip_offset; // typical ethernet

    memset(pkt, 0, sizeof(*pkt));

    while (pcap_next_ex(pcap_file, &pcap_header_ptr, &pcap_data) == 1) {
        memset(data_buffer, 0, PKT_BUF_BYTES);
        memcpy(data_buffer, pcap_data, pcap_header_ptr->caplen);

        *total_packets += 1;
        ip_offset = 14; // typical Ethernet

        // TODO: make multiple vlan friendly
        eth_type = ntohs(*(uint16_t *)((unsigned long)data_buffer + 12)); // pointer to Ethernet type
        if (eth_type == 0x8100) {
            // add 4 bytes for size of VLAN header
            DEBUG_PRINT("pkt[%u]: adding 4-bytes for VLAN header (type=0X%x)\n", *total_packets, eth_type);
            ip_offset += 4;
        }
        // ignore non-IP, non-VLAN packets
        else if (eth_type != 0x0800) {
            DEBUG_PRINT("pkt[%u]: non-IP packet (type=0X%x)\n", *total_packets, eth_type);
            continue;
        }

        iph = (iphdr_t *)((unsigned long)data_buffer + ip_offset);
        rtp_pcap_iph_byteswap(iph);

        // ignore non-UDP packets
        if (iph->protocol != IPPROTO_UDP) {
            DEBUG_PRINT("pkt[%u]: non-UDP packet (proto=%d)\n", *total_packets, iph->protocol);
            continue;
        }

        // if a different destination IP address, ignore it
        if ((filter->flags & FILTER_FLAG_DADDR_SET) && iph->daddr != filter->daddr) {
            DEBUG_PRINT(
                "pkt[%u]: address (0x%08x) does not match destination filter "
                "(0x%08x)\n",
                *total_packets,
                iph->daddr,
                filter->daddr
            );
            continue;
        }

        if ((filter->flags & FILTER_FLAG_SADDR_SET) && iph->saddr != filter->saddr) {
            DEBUG_PRINT(
                "pkt[%u]: address (0x%08x) does not match source "
                "filter (0x%08x)\n",
                *total_packets,
                iph->saddr,
                filter->saddr
            );
            continue;
        }

        udph = (udphdr_t *)((unsigned long)iph + (iph->ihl << 2));
        rtp_pcap_udph_byteswap(udph);

        // if a different destination UDP port, ignore it
        if ((filter->flags & FILTER_FLAG_DPORT_SET) && udph->dest != filter->dport) {
            DEBUG_PRINT(
                "pkt[%u]: port (0x%04x) does not match destination "
                "filter (0x%04x)\n",
                *total_packets,
                udph->dest,
                filter->dport
            );
            continue;
        }

        if ((filter->flags & FILTER_FLAG_SPORT_SET) && udph->source != filter->sport) {
            DEBUG_PRINT(
                "pkt[%u]: port (0x%04x) does not match source filter "
                "(0x%04x)\n",
                *total_packets,
                udph->source,
                filter->sport
            );
            continue;
        }

        // we've got a match, copy it to the packet
        pkt->pcap_hdr = *pcap_header_ptr;
        memcpy(pkt->buffer, data_buffer, sizeof(pkt->buffer));
        pkt->iph = (iphdr_t *)((unsigned long)pkt->buffer + (unsigned long)iph - (unsigned long)data_buffer);
        pkt->udph = (udphdr_t *)((unsigned long)pkt->buffer + (unsigned long)udph - (unsigned long)data_buffer);
        pkt->rtph = (rtphdr_t *)(pkt->udph + 1);
        return 0;
    } // while

    return -1;
}

int rtp_pcap_packet_get_rtp_payload_length(rtp_pcap_pkt_t *pkt) {
    int length = pkt->udph->len - sizeof(*(pkt->udph));
    return length - rtp_hdr_get_hdr_length(pkt->rtph);
}

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

        rtph = packet.rtph;
        if (RFC_1889_VERSION != rtp_hdr_get_version(rtph)) {
            fprintf(stderr, "%s: packet is not valid RTP (ver=%u)\n", progname, rtp_hdr_get_version(rtph));
            continue;
        }

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

long milliseconds(struct timeval *tv) { return long(tv->tv_usec / 1000); }

void rtp_pcap_details_time_display(
    time_display_t time_type, char *time_display, const size_t display_size, char *time_dspace, const size_t space_size,
    const struct timeval *pkttime, const struct timeval *lastpkt, const struct timeval *firstpkt
) {
    if (time_type == tdisp_prevpacket) {
        time_t sec = pkttime->tv_sec - lastpkt->tv_sec;
        unsigned long msecs = sec * 1000 + (pkttime->tv_usec - lastpkt->tv_usec) / 1000;
        snprintf(time_display, display_size, "%6lu", msecs);
        snprintf(time_dspace, space_size, "   ");
    } else if (time_type == tdisp_startcapture) {
        float seconds = pkttime->tv_sec - firstpkt->tv_sec + (float)(pkttime->tv_usec - firstpkt->tv_usec) / 1000000;
        snprintf(time_display, display_size, "%6.3f", seconds);
        snprintf(time_dspace, space_size, "   ");
    } else if (time_type == tdisp_timeofday) {
        struct timeval tv = *pkttime;
        time_t nowtime = tv.tv_sec;
        struct tm *nowtm;
        char tmbuf[64];

        nowtm = localtime(&nowtime);
        strftime(tmbuf, sizeof(tmbuf), "%H:%M:%S", nowtm);
        snprintf(time_display, display_size, "%s.%03ld", tmbuf, milliseconds(&tv));
        snprintf(time_dspace, space_size, "         ");
    } else if (time_type == tdisp_date) {
        struct timeval tv = *pkttime;
        time_t nowtime = tv.tv_sec;
        struct tm *nowtm;
        char tmbuf[64];

        nowtm = localtime(&nowtime);
        strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);
        snprintf(time_display, display_size, "%s.%03ld", tmbuf, milliseconds(&tv));
        snprintf(time_dspace, space_size, "                    ");
    } else {
        time_display[0] = '\0';
        time_dspace[0] = '\0';
    }
}

const char *rtp_pcap_details_analyze(
    char *output, size_t out_size, rtphdr_t *rtph, rtphdr_t *last_rtp, const rtpmap_t &rtpmap, uint32_t samples_per_packet, uint8_t dtmf_decode,
    uint8_t last_dtmf_event, uint32_t last_dtmf_time
) {
    rtp_event_t *dtmfh;

    *output = '\0';

    // tell why we're printing
    if (RFC_1889_VERSION != rtp_hdr_get_version(rtph)) {
        // only print this when
        if (rtp_hdr_get_version(last_rtp) != rtp_hdr_get_version(rtph)) {
            snprintf(output, out_size, "***** Invalid RTP version=%u ******\n", rtp_hdr_get_version(rtph));
        }
    } else if (rtp_hdr_get_ssrc(last_rtp) != rtp_hdr_get_ssrc(rtph)) {
        snprintf(output, out_size, "***** SSRC changed from %u to %u ******\n", rtp_hdr_get_ssrc(last_rtp), rtp_hdr_get_ssrc(rtph));
    } else if (rtp_hdr_get_ptype(last_rtp) != rtp_hdr_get_ptype(rtph)) {
        if (rtp_hdr_get_sequence(last_rtp) + 1 == rtp_hdr_get_sequence(rtph))
            snprintf(
                output,
                out_size,
                "***** Codec type change from %s(%u) to %s(%u) ******\n",
                rtp_pcap_rtpmap_get_string(rtpmap, rtp_hdr_get_ptype(last_rtp)),
                rtp_hdr_get_ptype(last_rtp),
                rtp_pcap_rtpmap_get_string(rtpmap, rtp_hdr_get_ptype(rtph)),
                rtp_hdr_get_ptype(rtph)
            );
        else
            snprintf(
                output,
                out_size,
                "***** Codec type change from %s(%u), seq=%u to %s(%u), seq=%u "
                "******\n",
                rtp_pcap_rtpmap_get_string(rtpmap, rtp_hdr_get_ptype(last_rtp)),
                rtp_hdr_get_ptype(last_rtp),
                rtp_hdr_get_sequence(last_rtp),
                rtp_pcap_rtpmap_get_string(rtpmap, rtp_hdr_get_ptype(rtph)),
                rtp_hdr_get_ptype(rtph),
                rtp_hdr_get_sequence(rtph)
            );
    } else if (rtp_hdr_get_sequence(last_rtp) + 1 != rtp_hdr_get_sequence(rtph)) {
        int delta = rtp_hdr_get_sequence(rtph) - rtp_hdr_get_sequence(last_rtp);

        // attempt to classify the nature of the sequence number discontinuity?
        if (delta > 0 && delta < RTP_STATS_WINDOW_PACKETS)
            snprintf(output, out_size, "***** Missed %u sequence numbers ******\n", delta - 1);
        else if (delta < 0 && delta > -RTP_STATS_WINDOW_PACKETS)
            snprintf(output, out_size, "***** Out of order RTP sequence number: back %d ******\n", -delta);
        else
            snprintf(
                output, out_size, "***** Sequence number jump: last=%u, curr=%u ******\n", rtp_hdr_get_sequence(last_rtp), rtp_hdr_get_sequence(rtph)
            );
    }
    // check this before doing the normal timestamp checking, since DTMF breaks
    // the timestamp rules
    else if (rtp_hdr_get_ptype(rtph) == dtmf_decode && rtp_hdr_get_timestamp(rtph) != last_dtmf_time) {
        // NOTE: this is a bit of a hack... it is getting a pointer beyond the
        // data structure assuming the DTMF payload is after it
        dtmfh = (rtp_event_t *)rtp_hdr_get_payload(rtph);
        snprintf(
            output,
            out_size,
            "***** New DTMF event: old id=%u, timestamp=%u; new id=%d, "
            "timestamp=%u ******\n",
            last_dtmf_event,
            last_dtmf_time,
            rtp_hdr_get_timestamp(rtph),
            rtp_event_get_event(dtmfh)
        );
    } else if (samples_per_packet != 0 && rtp_hdr_get_timestamp(last_rtp) + samples_per_packet != rtp_hdr_get_timestamp(rtph)) {
        if (rtp_hdr_get_marker(rtph))
            snprintf(
                output,
                out_size,
                "***** Marked silence gap of %u samples ******\n",
                rtp_hdr_get_timestamp(rtph) - rtp_hdr_get_timestamp(last_rtp) - samples_per_packet
            );
        else
            snprintf(
                output,
                out_size,
                "***** Timestamp discontinuity (possible silence): old(%u) + "
                "expected(%u) != new(%u) ******\n",
                rtp_hdr_get_timestamp(last_rtp),
                samples_per_packet,
                rtp_hdr_get_timestamp(rtph)
            );
    }

    return output;
}

const char *rtp_pcap_details_packet_display(
    char *output, size_t out_size, rtphdr_t *rtph, uint32_t index, const char *time_display, const rtpmap_t &rtpmap, uint8_t dtmf_decode,
    int payload_len
) {
    char payload_display[512];
    rtp_event_t *dtmfh;

    if (RFC_1889_VERSION != rtp_hdr_get_version(rtph)) {
        snprintf(output, out_size, "%6d %s RTP Invalid: version=%d\n", index, time_display, rtp_hdr_get_version(rtph));
    } else {
        if (rtp_hdr_get_ptype(rtph) == dtmf_decode) {
            // NOTE: this is a bit of a hack -- it assumes that the DTMF payload
            // follows the RTP header
            dtmfh = (rtp_event_t *)rtp_hdr_get_payload(rtph);
            snprintf(
                payload_display,
                sizeof(payload_display) - 1,
                ", DTMF id=%u, duration=%u%s",
                rtp_event_get_event(dtmfh),
                rtp_event_get_duration(dtmfh),
                (dtmfh->e ? " (end)" : "")
            );
        } else {
            snprintf(payload_display, sizeof(payload_display) - 1, ", payload bytes=%d", payload_len);
        }
        snprintf(
            output,
            out_size,
            "%6d %s Payload type=%s(%d), SSRC=0x%08X, Seq=%u, Time=%u%s%s\n",
            index,
            time_display,
            rtp_pcap_rtpmap_get_string(rtpmap, rtp_hdr_get_ptype(rtph)),
            rtp_hdr_get_ptype(rtph),
            rtp_hdr_get_ssrc(rtph),
            rtp_hdr_get_sequence(rtph),
            rtp_hdr_get_timestamp(rtph),
            rtp_hdr_get_marker(rtph) ? ", Mark" : "",
            payload_display
        );
    }

    return output;
}

const char *rtp_pcap_details_packet_summary(
    char *output, size_t out_size, rtphdr_t *last_rtp, uint32_t n_suppressed, uint32_t index_start, uint32_t index_end, const char *time_display,
    const rtpmap_t &rtpmap, uint8_t dtmf_decode, uint8_t last_dtmf_event, uint32_t samples_per_packet
) {
    char payload_display[512];

    payload_display[0] = '\0';

    // summarize skipped packets
    if (rtp_hdr_get_ptype(last_rtp) == dtmf_decode) {
        snprintf(payload_display, sizeof(payload_display) - 1, ", DTMF id=%u", last_dtmf_event);
    } else {
        snprintf(payload_display, sizeof(payload_display) - 1, ", Time=%u samples/pkt", samples_per_packet);
    }

    snprintf(
        output,
        out_size,
        "%6d-%d  %sPayload type=%s(%d), SSRC=0x%08X, Seq=%u-%u%s\n",
        index_start,
        index_end,
        time_display,
        rtp_pcap_rtpmap_get_string(rtpmap, rtp_hdr_get_ptype(last_rtp)),
        rtp_hdr_get_ptype(last_rtp),
        rtp_hdr_get_ssrc(last_rtp),
        rtp_hdr_get_sequence(last_rtp) - n_suppressed + 1,
        rtp_hdr_get_sequence(last_rtp) - 1,
        payload_display
    );

    return output;
}

void rtp_pcap_details(const char *progname, pcap_t *pcap_file, const rtpmap_t &rtpmap, rtp_pcap_filter_t *filter, rtp_pcap_details_args_t *args) {
    bool suppress = args->summarize;
    bool analysis = args->analyse;
    uint8_t dtmf_decode = args->dtmf_decode;
    time_display_t time_type = args->time_type;
    index_display_t index_type = args->index_type;
    rtphdr_t last_rtp; // on stack data structure to hold all RTP info from last
                       // packet
    uint8_t last_dtmf_event;
    uint32_t last_dtmf_time;
    int n_suppressed = 0;
    struct timeval last_clock;
    struct timeval first_clock;
    uint32_t samples_per_packet = 0;
    uint32_t total_pkt_count = 0;
    uint32_t stream_pkt_count = 0;
    uint32_t index_cur;
    uint32_t index_sup_first;
    uint32_t index_sup_last;
    char time_display[128]; // holds time strings
    char time_summary[128]; // holds blank spaces for summaries
    char pkt_display[512];
    char pkt_summary[512];
    rtp_pcap_pkt_t packet;     // on stack place to hold data
    rtphdr_t *rtph = NULL;     // pointer within current packet
    rtp_event_t *dtmfh = NULL; // pointer within current packet

    n_suppressed = 0;
    memset(pkt_display, 0, sizeof(pkt_display));
    memset(pkt_summary, 0, sizeof(pkt_summary));
    memset(time_display, 0, sizeof(time_display));
    memset(time_summary, 0, sizeof(time_summary));
    memset(&last_clock, 0, sizeof(last_clock));
    memset(&first_clock, 0, sizeof(first_clock));
    rtp_hdr_init(&last_rtp);

    do {
        int result = rtp_pcap_get_next_packet(pcap_file, &total_pkt_count, filter, &packet);
        if (0 != result) {
            // if we have any "suppressed packets", print out the balance
            if (n_suppressed) {
                rtp_pcap_details_packet_summary(
                    pkt_summary,
                    sizeof(pkt_summary),
                    &last_rtp,
                    n_suppressed,
                    index_sup_first,
                    index_sup_last,
                    time_summary,
                    rtpmap,
                    dtmf_decode,
                    last_dtmf_event,
                    samples_per_packet
                );
                fprintf(stdout, "%s", pkt_summary);
                fprintf(stdout, "%s", pkt_display);
            }
            break;
        }

        rtph = packet.rtph;
        if (stream_pkt_count == 0 && rtp_hdr_get_version(rtph) != RFC_1889_VERSION) {
            // ignore non-rtp streams
            continue;
        }

        stream_pkt_count++;
        index_cur = (index_type == idisp_stream ? stream_pkt_count : (index_type == idisp_pcap ? total_pkt_count : 0));

        // lock down the filter on the address/port, and initialize the clock
        if (stream_pkt_count == 1) {
            if (filter->flags & FILTER_FLAG_DST_FILTER) {
                filter->flags |= FILTER_FLAG_DADDR_SET | FILTER_FLAG_DPORT_SET;
                filter->daddr = packet.iph->daddr;
                filter->dport = packet.udph->dest;
            } else if (filter->flags & FILTER_FLAG_SRC_FILTER) {
                filter->flags |= FILTER_FLAG_SADDR_SET | FILTER_FLAG_SPORT_SET;
                filter->saddr = packet.iph->saddr;
                filter->sport = packet.udph->source;
            }
            last_clock = first_clock = packet.pcap_hdr.ts;
        }

        // prepare the buffers for time displays
        rtp_pcap_details_time_display(
            time_type, time_display, sizeof(time_display), time_summary, sizeof(time_summary), &packet.pcap_hdr.ts, &last_clock, &first_clock
        );

        // print the packets out in a tcpdump fashion, according to input (if
        // not suppressing or anything changed)
        if (!suppress || rtp_hdr_get_version(rtph) != RFC_1889_VERSION || rtp_hdr_get_marker(rtph) ||
            rtp_hdr_get_ssrc(&last_rtp) != rtp_hdr_get_ssrc(rtph) || rtp_hdr_get_sequence(&last_rtp) + 1 != rtp_hdr_get_sequence(rtph) ||
            rtp_hdr_get_ptype(&last_rtp) != rtp_hdr_get_ptype(rtph) ||
            (samples_per_packet != 0 && rtp_hdr_get_timestamp(&last_rtp) + samples_per_packet != rtp_hdr_get_timestamp(rtph)) ||
            (rtp_hdr_get_ptype(rtph) == dtmf_decode && rtp_hdr_get_timestamp(rtph) != last_dtmf_time)) {
            if (n_suppressed != 0) {
                // summarize skipped packets, if more than the currently
                // buffered
                if (n_suppressed > 1) {
                    rtp_pcap_details_packet_summary(
                        pkt_summary,
                        sizeof(pkt_summary),
                        &last_rtp,
                        n_suppressed,
                        index_sup_first,
                        index_sup_last,
                        time_summary,
                        rtpmap,
                        dtmf_decode,
                        last_dtmf_event,
                        samples_per_packet
                    );
                    fprintf(stdout, "%s", pkt_summary);
                }

                // dump the last packet
                fprintf(stdout, "%s", pkt_display);
                // reset the buffer
                n_suppressed = 0;
            }

            // if analyzing (and not the first packet)
            if (analysis && stream_pkt_count > 1) {
                char analysis[512];
                rtp_pcap_details_analyze(
                    analysis, sizeof(analysis), rtph, &last_rtp, rtpmap, samples_per_packet, dtmf_decode, last_dtmf_event, last_dtmf_time
                );
                if (strlen(analysis) != 0) {
                    fprintf(stdout, "%s", analysis);
                }
            }

            rtp_pcap_details_packet_display(
                pkt_display, sizeof(pkt_display), rtph, index_cur, time_display, rtpmap, dtmf_decode, rtp_pcap_packet_get_rtp_payload_length(&packet)
            );
            fprintf(stdout, "%s", pkt_display);
        } else {
            // buffer the data, so we can dump it out at the end of the file
            n_suppressed++;
            if (n_suppressed == 1) {
                index_sup_first = (index_type == idisp_stream ? stream_pkt_count : (index_type == idisp_pcap ? total_pkt_count : 0));
                index_sup_last = index_sup_first;
            } else {
                index_sup_last = (index_type == idisp_stream ? stream_pkt_count : (index_type == idisp_pcap ? total_pkt_count : 0));
            }

            rtp_pcap_details_packet_display(
                pkt_display, sizeof(pkt_display), rtph, index_cur, time_display, rtpmap, dtmf_decode, rtp_pcap_packet_get_rtp_payload_length(&packet)
            );
        }

        // if current packet is valid RTP, check a few things (before
        // overwriting stored header)
        if (RFC_1889_VERSION == rtp_hdr_get_version(rtph)) {
            // reset samples per packet if changing codecs or SSRCs
            if (rtp_hdr_get_ssrc(&last_rtp) != rtp_hdr_get_ssrc(rtph) || rtp_hdr_get_ptype(&last_rtp) != rtp_hdr_get_ptype(rtph)) {
                samples_per_packet = 0;
            }
            // if samples per packet has not been calculated, make sure we use
            // consecutive packets
            else if (samples_per_packet == 0 && RFC_1889_VERSION == rtp_hdr_get_version(&last_rtp) &&
                     rtp_hdr_get_sequence(&last_rtp) + 1 == rtp_hdr_get_sequence(rtph)) {
                samples_per_packet = rtp_hdr_get_timestamp(rtph) - rtp_hdr_get_timestamp(&last_rtp);
            }

            if (rtp_hdr_get_ptype(rtph) == dtmf_decode) {
                dtmfh = (rtp_event_t *)rtp_hdr_get_payload(rtph);
                last_dtmf_event = rtp_event_get_event(dtmfh);
                last_dtmf_time = rtp_hdr_get_timestamp(rtph);
            } else {
                last_dtmf_event = 255;
                last_dtmf_time = -1;
            }
        }

        // store information from the last packet -- regardless of type
        last_clock = packet.pcap_hdr.ts;
        last_rtp = *rtph;

    } while (1);
}

void rtp_pcap_list(const char *progname, pcap_t *pcap_file, const rtpmap_t &rtpmap, rtp_pcap_filter_t *filter, rtp_pcap_list_args_t *args) {
    bool odd = args->odd;
    bool all_udp = args->all_udp;
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
                fprintf(stdout, "      %s (%u) : %u\n", rtp_pcap_rtpmap_get_string(rtpmap, icount->first), icount->first, icount->second);
            }
        }
    }
}

srtp_algorithm_t rtp_pcap_parse_srtp_alg(const char *algstr) {
    if (NULL == algstr) {
        return srtp_alg_none;
    }
    if (NULL != strstr(algstr, "32")) {
        return srtp_alg_aes128_sha1_32bit;
    }
    if (NULL != strstr(algstr, "80")) {
        return srtp_alg_aes128_sha1_80bit;
    }

    return srtp_alg_none;
}

const char *rtp_pcap_algorithm_string(srtp_algorithm_t alg) {
    if (srtp_alg_none == alg) {
        return "none";
    }
    if (srtp_alg_aes128_sha1_32bit == alg) {
        return "AES-CM-128-SHA1-32bit";
    }
    if (srtp_alg_aes128_sha1_80bit == alg) {
        return "AES-CM-128-SHA1-80bit";
    }

    return "unknown";
}

const char *rtp_pcap_cryptop_string(cryptop_t op) {
    if (cryptop_encrypt == op) {
        return "encrypt";
    }
    if (cryptop_decrypt == op) {
        return "decrypt";
    }
    return "unknown";
}

static inline const char *rtp_pcap_get_srtp_error_string(srtp_err_status_t status) {
    switch (status) {
    case srtp_err_status_ok:
        return "none";
    case srtp_err_status_fail:
        return "unspecified";
    case srtp_err_status_bad_param:
        return "bad parameter";
    case srtp_err_status_alloc_fail:
        return "allocation failure";
    case srtp_err_status_dealloc_fail:
        return "deallocation failure";
    case srtp_err_status_init_fail:
        return "init failure";
    case srtp_err_status_terminus:
        return "counter expired";
    case srtp_err_status_auth_fail:
        return "authentication failure";
    case srtp_err_status_cipher_fail:
        return "cipher failure";
    case srtp_err_status_replay_fail:
        return "replay bad index";
    case srtp_err_status_replay_old:
        return "replay old index";
    case srtp_err_status_algo_fail:
        return "algorithm failure";
    case srtp_err_status_no_such_op:
        return "unsupported op";
    case srtp_err_status_no_ctx:
        return "no context";
    case srtp_err_status_cant_check:
        return "invalid op";
    case srtp_err_status_key_expired:
        return "key expired";
    case srtp_err_status_socket_err:
        return "socket failure";
    case srtp_err_status_signal_err:
        return "signal failure";
    case srtp_err_status_nonce_bad:
        return "bad nonce";
    case srtp_err_status_read_fail:
        return "read failure";
    case srtp_err_status_write_fail:
        return "write failure";
    case srtp_err_status_parse_err:
        return "parse failure";
    case srtp_err_status_encode_err:
        return "encoding failure";
    case srtp_err_status_semaphore_err:
        return "semaphore failure";
    case srtp_err_status_pfkey_err:
        return "key derivation failure";
    case srtp_err_status_bad_mki:
        return "bad MKI";
    case srtp_err_status_pkt_idx_old:
        return "old packet index";
    case srtp_err_status_pkt_idx_adv:
        return "future packet index";
    }

    return "unknown";
}

bool isxstring(const char *input) {
    for (const char *i = input; *i != 0; i++) {
        if (!isxdigit(*i)) {
            return false;
        }
    }

    return true;
}

int parse_srtp_key(unsigned char *output, const char *input) {
    if (isxstring(input)) {
        return hexString2Binary(output, input);
    }

    size_t out_len = 0;
    unsigned char *decoded = base64_decode((const unsigned char *)input, strlen(input), &out_len);
    memcpy(output, decoded, out_len);
    return out_len;
}

void srtp_log_print(srtp_log_level_t level, const char *msg, void *data) {
    // Simple handler to print logs to console
    printf("SRTP-LOG [%d]: %s\n", level, msg);
}

void rtp_pcap_srtp(const char *progname, pcap_t *input, rtp_pcap_filter_t *filter, rtp_pcap_srtp_args_t *args) {
    struct stat mystat;
    pcap_t *output;
    pcap_dumper_t *dumper;
    rtp_pcap_pkt_t packet;
    uint32_t total_pkt_count = 0;
    uint32_t stream_pkt_count = 0;
    uint32_t write_pkt_count = 0;
    uint32_t srtp_fail_count = 0;
    uint8_t master_key[128];
    srtp_err_status_t srtp_status;
    srtp_policy_t srtp_policy;
    srtp_t srtp_sess;
    int orig_length;
    int rtp_length;
    int delta_length;
    int key_length;

    memset(&srtp_sess, 0, sizeof(srtp_sess));
    memset(&srtp_policy, 0, sizeof(srtp_policy));

    if (args->alg == srtp_alg_none) {
        fprintf(stdout, "\n%s: invalid algorithm specified!\n", progname);
        return;
    }

    if (args->key.length() == 0) {
        fprintf(stdout, "\n%s: no key specified!\n", progname);
        return;
    }

    if (args->key.length() > 128) {
        fprintf(stdout, "\n%s: key length is too long (%zu)!\n", progname, args->key.length());
        return;
    }

    // initialize the master key from the hex string
    memset(master_key, 0, sizeof(master_key));
    key_length = parse_srtp_key(master_key, args->key.c_str());
    if (key_length <= 0 || key_length > 32) {
        fprintf(stdout, "\n%s: invalid key length (%u) for '%s'!\n", progname, key_length, args->key.c_str());
        return;
    }

    if (args->outfile.length() == 0) {
        fprintf(stdout, "\n%s: no output file specified!\n", progname);
        return;
    }

    // make sure output file does not exist -- don't want to worry about overwriting
    if (!args->force && 0 == stat(args->outfile.c_str(), &mystat)) {
        fprintf(stdout, "\n%s: output file (%s) already exists!\n", progname, args->outfile.c_str());
        return;
    }

    srtp_status = srtp_init();
    if (srtp_err_status_ok != srtp_status) {
        fprintf(stdout, "\n%s: failed to initialize srtp: %d!\n", progname, srtp_status);
        return;
    }

    srtp_install_log_handler(srtp_log_print, NULL);

    // turn on debug before creating/initializing the contexts, so those operations are visible
    if (args->debug) {
        srtp_set_debug_module("srtp", 1);
        srtp_set_debug_module("cipher", 1);
        srtp_set_debug_module("aes icm", 1);
        srtp_set_debug_module("auth func", 1);
        srtp_set_debug_module("hmac sha1", 1);
    }

    // initialize the policy that is used to create the context
    srtp_policy.next = NULL;
    srtp_policy.ssrc.type = (args->op == cryptop_encrypt ? ssrc_any_outbound : ssrc_any_inbound);
    srtp_policy.ssrc.value = 0;
    srtp_policy.key = master_key;
    srtp_crypto_policy_set_rtcp_default(&srtp_policy.rtcp);
    if (args->alg == srtp_alg_aes128_sha1_32bit) {
        srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&srtp_policy.rtp);
    } else {
        srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&srtp_policy.rtp);
    }

    // create the SRTP context
    srtp_status = srtp_create(&srtp_sess, &srtp_policy);
    if (srtp_err_status_ok != srtp_status) {
        fprintf(stdout, "\n%s: failed to create srtp context: %d!\n", progname, srtp_status);
        return;
    }

    output = pcap_open_dead_with_tstamp_precision(pcap_datalink(input), pcap_snapshot(input), pcap_get_tstamp_precision(input));
    if (NULL == output) {
        fprintf(stdout, "\n%s: unable to create output pcap!\n", progname);
        return;
    }

    dumper = pcap_dump_open(output, args->outfile.c_str());
    if (NULL == dumper) {
        fprintf(stdout, "\n%s: unable to open output file (%s)!\n", progname, args->outfile.c_str());
        return;
    }

    do {
        int result = rtp_pcap_get_next_packet(input, &total_pkt_count, filter, &packet);
        if (0 != result) {
            break;
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
        rtp_length = orig_length = packet.udph->len - sizeof(udphdr_t);

        if (args->op == cryptop_encrypt) {
            // TODO: distinguish RTP/RTCP
            srtp_status = srtp_protect(srtp_sess, packet.rtph, &rtp_length);
        } else {
            // TODO: distinguish SRTP/SRTCP
            srtp_status = srtp_unprotect(srtp_sess, packet.rtph, &rtp_length);
        }

        if (srtp_status != srtp_err_status_ok) {
            fprintf(
                stdout,
                "\n%s of packet[%d] failed: %s (%d)",
                rtp_pcap_cryptop_string(args->op),
                stream_pkt_count - 1,
                rtp_pcap_get_srtp_error_string(srtp_status),
                srtp_status
            );
            srtp_fail_count++;
            continue;
        }

        // adjust the packet
        delta_length = rtp_length - orig_length;
        packet.pcap_hdr.len += delta_length;
        packet.pcap_hdr.caplen += delta_length;
        packet.iph->tot_len += delta_length;
        packet.udph->len += delta_length;
        // TODO: recalculate checksums (instead of zero'ing out below)?
        packet.iph->check = 0;
        packet.udph->check = 0;

        // put things back into network byte order before writing to file
        rtp_pcap_iph_byteswap(packet.iph);
        rtp_pcap_udph_byteswap(packet.udph);

        // write the packet to the output
        pcap_dump((u_char *)dumper, &packet.pcap_hdr, packet.buffer);
        write_pkt_count++;
    } while (1);

    fprintf(stdout, "\n");
    fprintf(stdout, "\n%s: %s results", progname, rtp_pcap_cryptop_string(args->op));
    fprintf(stdout, "\n    %s key[%d]=%s", rtp_pcap_algorithm_string(args->alg), key_length, bin2hexString(master_key, key_length));
    fprintf(stdout, "\n    srtp failures=%u", srtp_fail_count);
    fprintf(stdout, "\n    wrote %u packets to %s", write_pkt_count, args->outfile.c_str());
    fprintf(stdout, "\n");

    srtp_dealloc(srtp_sess);
    pcap_dump_close(dumper);
    pcap_close(output);
}

int main(int argc, char *argv[]) {
    char *progname;
    char *filename = NULL;
    char default_action[] = ARG_ACT_SUMMARY; // default to summary
    char *action = default_action;
    char error_buf[512];
    char *tmp;
    char *addr = NULL;
    char *port = NULL;
    struct stat mystat;
    rtp_pcap_filter_t filter;
    rtpmap_t rtpmap;
    pcap_t *pcap_file;
    rtp_pcap_details_args_t detail_args;
    rtp_pcap_list_args_t list_args;
    rtp_pcap_srtp_args_t srtp_args;
    int i;
    int rval = 0;

    // determine the basename
    tmp = strchr(argv[0], '/');
    progname = (NULL == tmp ? argv[0] : tmp + 1);

    // initialize some stuff
    memset(&filter, 0, sizeof(filter));
    filter.flags = FILTER_FLAG_DST_FILTER;
    rtp_pcap_rtpmap_init(rtpmap);
    detail_args.analyse = true;
    detail_args.summarize = true;
    detail_args.dtmf_decode = RTP_PTYPE_DTMF_DEFAULT;
    detail_args.time_type = tdisp_none;
    detail_args.index_type = idisp_pcap;
    list_args.odd = false;
    list_args.all_udp = false;
    srtp_args.op = cryptop_none;
    srtp_args.alg = srtp_alg_aes128_sha1_32bit;
    srtp_args.outfile = "output.pcap";
    srtp_args.force = false;
    srtp_args.debug = false;

    // be friendly when no args are provided
    if (1 == argc) {
        usage(progname);
        return 0;
    }

    // parse the arguments
    for (i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (0 == strcasecmp(ARG_FILE, arg)) {
            filename = NEXT_ARG(i, argc, argv);
        } else if (0 == strcasecmp(ARG_FILTER, arg)) {
            char *type = NEXT_ARG(i, argc, argv);
            if (type != NULL) {
                if (NULL != strstr(type, "src")) {
                    filter.flags = FILTER_FLAG_SRC_FILTER;
                }
            }
        } else if (0 == strcasecmp(ARG_ADDR, arg)) {
            addr = NEXT_ARG(i, argc, argv);
        } else if (0 == strcasecmp(ARG_PORT, arg)) {
            port = NEXT_ARG(i, argc, argv);
        } else if (0 == strcasecmp(ARG_DTMF, arg)) {
            char *ptypestr = NEXT_ARG(i, argc, argv);
            if (ptypestr != NULL) {
                detail_args.dtmf_decode = atoi(ptypestr);
            }
        } else if (0 == strcasecmp(ARG_TIME, arg)) {
            detail_args.time_type = rtp_pcap_time_display_parse(NEXT_ARG(i, argc, argv));
        } else if (0 == strcasecmp(ARG_INDEX, arg)) {
            detail_args.index_type = rtp_pcap_index_display_parse(NEXT_ARG(i, argc, argv));
        } else if (0 == strcasecmp(ARG_ALL, arg)) {
            detail_args.summarize = false;
            list_args.all_udp = true;
        } else if (0 == strcasecmp(ARG_QUIET, arg)) {
            detail_args.analyse = false;
        } else if (0 == strcasecmp(ARG_ODD, arg)) {
            list_args.odd = true;
        } else if (0 == strcasecmp(ARG_MAP, arg)) {
            rtp_pcap_rtpmap_parse_arg(rtpmap, NEXT_ARG(i, argc, argv));
        } else if (0 == strcasecmp(ARG_ALG, arg)) {
            srtp_args.alg = rtp_pcap_parse_srtp_alg(NEXT_ARG(i, argc, argv));
        } else if (0 == strcasecmp(ARG_KEY, arg)) {
            srtp_args.key = NEXT_ARG(i, argc, argv);
        } else if (0 == strcasecmp(ARG_OUTPUT, arg)) {
            srtp_args.outfile = NEXT_ARG(i, argc, argv);
        } else if (0 == strcasecmp(ARG_FORCE, arg)) {
            srtp_args.force = true;
        } else if (0 == strcasecmp(ARG_DEBUG, arg)) {
            srtp_args.debug = true;
        } else if (0 == strcasecmp(ARG_ACT_SUMMARY, arg)) {
            action = arg;
        } else if (0 == strcasecmp(ARG_ACT_DETAILS, arg)) {
            action = arg;
        } else if (0 == strcasecmp(ARG_ACT_LIST, arg)) {
            action = arg;
        } else if (0 == strcasecmp(ARG_ACT_DECRYPT, arg)) {
            action = arg;
        } else if (0 == strcasecmp(ARG_ACT_ENCRYPT, arg)) {
            action = arg;
        } else if (0 == strcasecmp(ARG_HELP, arg) || 0 == strcasecmp("help", arg)) {
            usage(progname);
            return 0;
        } else {
            usage(progname);
            fprintf(stdout, "\n%s: invalid argument '%s'\n", progname, arg);
            return 1;
        }
    } // for - arg parsing

    // finish initializing the filter
    if (filter.flags & FILTER_FLAG_DST_FILTER) {
        if (addr != NULL) {
            filter.flags |= FILTER_FLAG_DADDR_SET;
            filter.daddr = inet_network(addr);
        }
        if (port != NULL) {
            filter.flags |= FILTER_FLAG_DPORT_SET;
            filter.dport = atoi(port);
        }
    } else {
        if (addr != NULL) {
            filter.flags |= FILTER_FLAG_SADDR_SET;
            filter.saddr = inet_network(addr);
        }
        if (port != NULL) {
            filter.flags |= FILTER_FLAG_SPORT_SET;
            filter.sport = atoi(port);
        }
    }

    if (NULL == filename) {
        usage(progname);
        fprintf(stdout, "\n%s: missing filename\n", progname);
        return -1;
    }

    if (NULL == action) {
        usage(progname);
        fprintf(stdout, "\n%s: no action specified\n", progname);
        return -1;
    }

    if (0 != stat(filename, &mystat)) {
        fprintf(stdout, "\n%s: missing file=%s\n", progname, filename);
        return -2;
    }

    pcap_file = pcap_open_offline(filename, error_buf);
    if (NULL == pcap_file) {
        fprintf(stdout, "\n%s: failed to open PCAP=%s: %s\n", progname, filename, error_buf);
        return -3;
    }

    if (0 == strcasecmp(action, ARG_ACT_SUMMARY)) {
        rtp_pcap_summary(progname, pcap_file, rtpmap, &filter);
    } else if (0 == strcasecmp(action, ARG_ACT_DETAILS)) {
        rtp_pcap_details(progname, pcap_file, rtpmap, &filter, &detail_args);
    } else if (0 == strcasecmp(action, ARG_ACT_LIST)) {
        rtp_pcap_list(progname, pcap_file, rtpmap, &filter, &list_args);
    } else if (0 == strcasecmp(action, ARG_ACT_ENCRYPT)) {
        srtp_args.op = cryptop_encrypt;
        rtp_pcap_srtp(progname, pcap_file, &filter, &srtp_args);
    } else if (0 == strcasecmp(action, ARG_ACT_DECRYPT)) {
        srtp_args.op = cryptop_decrypt;
        rtp_pcap_srtp(progname, pcap_file, &filter, &srtp_args);
    } else {
        fprintf(stdout, "%s: unhandled action='%s'\n", progname, action);
        rval = -4;
    }

    pcap_close(pcap_file);
    return rval;
}
