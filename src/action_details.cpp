#include <algorithm>
#include <cctype> // for tolower()
#include <cstdio>
#include <cstdlib> // for atoi()
#include <cstring> // for memset()
#include <ctime>
#include <string>

#include <pcap/pcap.h>

#include "action_details.h"
#include "arguments.h"
#include "packet_utilities.h"
#include "rtp_utils.h"
#include "time_utilities.h"

using namespace std;

#define ARG_DTMF "--dtmf"
#define ARG_ALL "--all"
#define ARG_QUIET "--quiet"
#define ARG_INDEX "--index"
#define ARG_TIME "--time"

#define AFMT_DTMF "<num>"
#define AFMT_INDEX "<pcap|stream>"
#define AFMT_TIME "<none|previous|capture|timeofday|date>"

typedef enum {
    idisp_stream,
    idisp_pcap,
} index_display_t;

typedef struct {
    bool analyse;
    bool summarize;
    uint8_t dtmf_decode;
    time_display_t time_type;
    index_display_t index_type;
} rtp_pcap_details_args_t;

static const ArgDefList details_options = {
    {ARG_ALL, "", "Print all packets in stream"},
    {ARG_QUIET, "", "Do NOT provide analysis comments on stream"},
    {ARG_INDEX, AFMT_INDEX, "Index type (default is stream)"},
    {ARG_TIME, AFMT_TIME, "Time display format (default=none)"},
    {ARG_DTMF, AFMT_DTMF, "RTP payload type for DTMF decodes (default=101)"},
};

static index_display_t parse_index_display(const char *arg) {
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

int rtp_pcap_packet_get_rtp_payload_length(rtp_pcap_pkt_t *pkt) {
    int length = pkt->udph->len - sizeof(*(pkt->udph));
    return length - rtp_hdr_get_hdr_length(pkt->rtph);
}

bool is_next_rtp_sequence(rtphdr_t *last, rtphdr_t *curr) { return ((rtp_hdr_get_sequence(last) + 1) & 0xffff) == rtp_hdr_get_sequence(curr); }

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
        if (is_next_rtp_sequence(last_rtp, rtph))
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
    } else if (!is_next_rtp_sequence(last_rtp, rtph)) {
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
        (rtp_hdr_get_sequence(last_rtp) - n_suppressed + 1) & 0xffff,
        rtp_hdr_get_sequence(last_rtp) - 1,
        payload_display
    );

    return output;
}

static void
rtp_pcap_details(const char *progname, pcap_t *pcap_file, const rtpmap_t &rtpmap, rtp_pcap_filter_t *filter, rtp_pcap_details_args_t *args) {
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
    bool first_packet = true;
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

        if (first_packet) {
            first_clock = packet.pcap_hdr.ts;
            first_packet = false;
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
            last_clock = packet.pcap_hdr.ts;
        }

        // prepare the buffers for time displays
        rtp_pcap_details_time_display(
            time_type, time_display, sizeof(time_display), time_summary, sizeof(time_summary), &packet.pcap_hdr.ts, &last_clock, &first_clock
        );

        // print the packets out in a tcpdump fashion, according to input (if
        // not suppressing or anything changed)
        if (!suppress || rtp_hdr_get_version(rtph) != RFC_1889_VERSION || rtp_hdr_get_marker(rtph) ||
            rtp_hdr_get_ssrc(&last_rtp) != rtp_hdr_get_ssrc(rtph) || !is_next_rtp_sequence(&last_rtp, rtph) ||
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
            else if (samples_per_packet == 0 && RFC_1889_VERSION == rtp_hdr_get_version(&last_rtp) && is_next_rtp_sequence(&last_rtp, rtph)) {
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

static void usage(const char *progname) { rtp_pcap_action_usage(progname, ARG_ACT_DETAILS, details_options); }

int run_details(const char *progname, int argc, char *argv[]) {
    CommonArgs common;

    rtp_pcap_details_args_t args;
    args.analyse = true;
    args.summarize = true;
    args.dtmf_decode = RTP_PTYPE_DTMF_DEFAULT;
    args.time_type = tdisp_none;
    args.index_type = idisp_pcap;

    ArgParser parser(argc, argv);
    parser.skip_action(ARG_ACT_DETAILS);

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

        if (parser.is(ARG_DTMF)) {
            const char *value = parser.require(ARG_DTMF, error, sizeof(error));
            if (value == NULL) {
                break;
            }
            args.dtmf_decode = atoi(value);
            common.rtpmap[args.dtmf_decode] = "telephone-events";
        } else if (parser.is(ARG_TIME)) {
            const char *value = parser.require(ARG_TIME, error, sizeof(error));
            if (value == NULL) {
                break;
            }
            args.time_type = rtp_pcap_time_display_parse(value);
        } else if (parser.is(ARG_INDEX)) {
            const char *value = parser.require(ARG_INDEX, error, sizeof(error));
            if (value == NULL) {
                break;
            }
            args.index_type = parse_index_display(value);
        } else if (parser.is(ARG_ALL)) {
            args.summarize = false;
        } else if (parser.is(ARG_QUIET)) {
            args.analyse = false;
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
    rtp_pcap_details(progname, pcap_file, common.rtpmap, &filter, &args);
    pcap_close(pcap_file);
    return 0;
}
