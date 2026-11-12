#include <algorithm>
#include <arpa/inet.h> // for inet_network()
#include <string.h>    // for memset()
#include <string>
#include <strings.h> // for strcasecmp()
#include <sys/stat.h>

#include <pcap/pcap.h>

#include "action_details.h"
#include "action_list.h"
#include "action_srtp.h"
#include "action_stats.h"
#include "action_summary.h"
#include "arguments.h"

using namespace std;

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// Macros/constants
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
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
#define ARG_ACT_STATS "stats"

#define SECTION_FMT "  %-20s\n"
#define HELP_FMT "      %-7s %-8s: %s\n"
#define ACTION_FMT "    %10s : %s\n"

// safe way to get the next string based on i
#define NEXT_ARG(i, c, v) (i + 1 < c ? v[++i] : NULL)

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
    fprintf(stdout, ACTION_FMT, ARG_ACT_STATS, "Provide RTP packet statistics for a stream");
#if INCLUDE_SRTP
    fprintf(stdout, ACTION_FMT, ARG_ACT_ENCRYPT, "Encrypt single RTP stream to another PCAP");
    fprintf(stdout, ACTION_FMT, ARG_ACT_DECRYPT, "Decrypt single RTP stream to another PCAP");
#endif // INCLUDE_SRTP
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
    fprintf(stdout, SECTION_FMT, "stats arguments");
    fprintf(stdout, HELP_FMT, ARG_TIME, AFMT_TIME, "Time display format (default=capture)");
    fprintf(stdout, "\n");
#if INCLUDE_SRTP
    fprintf(stdout, SECTION_FMT, "SRTP encrypt/decrypt arguments");
    fprintf(stdout, HELP_FMT, ARG_ALG, AFMT_ALG, "Cryptographic algorithm suite (default=aes128-sha1-32)");
    fprintf(stdout, HELP_FMT, ARG_KEY, AFMT_KEY, "Master key in hexidecimal format");
    fprintf(stdout, HELP_FMT, ARG_OUTPUT, AFMT_OUTPUT, "Output filename (default=output.pcap)");
    fprintf(stdout, HELP_FMT, ARG_FORCE, AFMT_FORCE, "Overwrite existing output file");
    fprintf(stdout, HELP_FMT, ARG_DEBUG, AFMT_DEBUG, "Turn on libSRTP debug");
    fprintf(stdout, "\n");
#endif // INCLUDE_SRTP
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
    rtp_pcap_stats_args_t stats_args;
#if INCLUDE_SRTP
    rtp_pcap_srtp_args_t srtp_args;
#endif // INCLUDE_SRTP
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
    stats_args.time_type = time_display_t::tdisp_startcapture;
#if INCLUDE_SRTP
    srtp_args.op = cryptop_none;
    srtp_args.alg = srtp_alg_aes128_sha1_32bit;
    srtp_args.outfile = "output.pcap";
    srtp_args.force = false;
    srtp_args.debug = false;
#endif // INCLUDE_SRTP

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
                rtpmap[detail_args.dtmf_decode] = "telephone-events";
            }
        } else if (0 == strcasecmp(ARG_TIME, arg)) {
            detail_args.time_type = rtp_pcap_time_display_parse(NEXT_ARG(i, argc, argv));
            stats_args.time_type = detail_args.time_type;
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
#if INCLUDE_SRTP
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
#endif // INCLUDE_SRTP
        } else if (0 == strcasecmp(ARG_ACT_SUMMARY, arg)) {
            action = arg;
        } else if (0 == strcasecmp(ARG_ACT_DETAILS, arg)) {
            action = arg;
        } else if (0 == strcasecmp(ARG_ACT_LIST, arg)) {
            action = arg;
        } else if (0 == strcasecmp(ARG_ACT_STATS, arg)) {
            action = arg;
#if INCLUDE_SRTP
        } else if (0 == strcasecmp(ARG_ACT_DECRYPT, arg)) {
            action = arg;
        } else if (0 == strcasecmp(ARG_ACT_ENCRYPT, arg)) {
            action = arg;
#endif // INCLUDE_SRTP
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
#if INCLUDE_SRTP
    } else if (0 == strcasecmp(action, ARG_ACT_ENCRYPT)) {
        srtp_args.op = cryptop_encrypt;
        rtp_pcap_srtp(progname, pcap_file, &filter, &srtp_args);
    } else if (0 == strcasecmp(action, ARG_ACT_DECRYPT)) {
        srtp_args.op = cryptop_decrypt;
        rtp_pcap_srtp(progname, pcap_file, &filter, &srtp_args);
#endif // INCLUDE_SRTP
    } else if (0 == strcasecmp(action, ARG_ACT_STATS)) {
        rtp_pcap_stats(progname, pcap_file, &filter, &stats_args);
    } else {
        fprintf(stdout, "%s: unhandled action='%s'\n", progname, action);
        rval = -4;
    }

    pcap_close(pcap_file);
    return rval;
}
