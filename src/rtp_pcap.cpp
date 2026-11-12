#include <stdio.h>
#include <string.h>  // for strchr()
#include <strings.h> // for strcasecmp()

#include "action_details.h"
#include "action_list.h"
#if INCLUDE_SRTP
#include "action_srtp.h"
#endif // INCLUDE_SRTP
#include "action_stats.h"
#include "action_summary.h"
#include "arguments.h"
#include "packet_utilities.h"

#define ACTION_FMT "    %10s : %s\n"

static bool is_action(const char *arg, const char *name) { return arg != NULL && 0 == strcasecmp(arg, name); }

static const char *find_action(int argc, char *argv[]) {
    if (argc < 2) {
        return NULL;
    }

    const char *arg = argv[1];
    if (
        is_action(arg, ARG_ACT_SUMMARY) || is_action(arg, ARG_ACT_DETAILS) || is_action(arg, ARG_ACT_LIST) || is_action(arg, ARG_ACT_STATS)
#if INCLUDE_SRTP
        || is_action(arg, ARG_ACT_ENCRYPT) || is_action(arg, ARG_ACT_DECRYPT)
#endif // INCLUDE_SRTP
    ) {
        return arg;
    }
    return NULL;
}

static void usage(const char *progname) {
    fprintf(stdout, "\n%s usage:\n\n", progname);
    fprintf(stdout, "  %s <action> [arguments]\n\n", progname);
    fprintf(stdout, "  Actions\n");
    fprintf(stdout, ACTION_FMT, ARG_ACT_LIST, "List all RTP streams");
    fprintf(stdout, ACTION_FMT, ARG_ACT_SUMMARY, "Summarize the RTP stream");
    fprintf(stdout, ACTION_FMT, ARG_ACT_DETAILS, "Provide RTP packet details");
    fprintf(stdout, ACTION_FMT, ARG_ACT_STATS, "Provide RTP packet statistics for a stream");
#if INCLUDE_SRTP
    fprintf(stdout, ACTION_FMT, ARG_ACT_ENCRYPT, "Encrypt single RTP stream to another PCAP");
    fprintf(stdout, ACTION_FMT, ARG_ACT_DECRYPT, "Decrypt single RTP stream to another PCAP");
#endif // INCLUDE_SRTP
    fprintf(stdout, "\n");
    fprintf(stdout, "  Use \"%s <action> %s\" for action argument info.\n\n", progname, ARG_HELP);
}

int main(int argc, char *argv[]) {
    char *tmp;
    const char *progname;
    const char *action;

    // determine the basename
    tmp = strchr(argv[0], '/');
    progname = (NULL == tmp ? argv[0] : tmp + 1);

    action = find_action(argc, argv);
    if (NULL == action) {
        bool help = (1 == argc);
        for (int i = 1; i < argc; i++) {
            if (rtp_pcap_arg_is_help(argv[i])) {
                help = true;
            } else {
                help = false;
                break;
            }
        }
        usage(progname);
        if (!help) {
            fprintf(stdout, "\n%s: no action specified\n", progname);
            return 1;
        }
        return 0;
    }

    if (0 == strcasecmp(action, ARG_ACT_SUMMARY)) {
        return run_summary(progname, argc, argv);
    } else if (0 == strcasecmp(action, ARG_ACT_DETAILS)) {
        return run_details(progname, argc, argv);
    } else if (0 == strcasecmp(action, ARG_ACT_LIST)) {
        return run_list(progname, argc, argv);
#if INCLUDE_SRTP
    } else if (0 == strcasecmp(action, ARG_ACT_ENCRYPT)) {
        return run_encrypt(progname, argc, argv);
    } else if (0 == strcasecmp(action, ARG_ACT_DECRYPT)) {
        return run_decrypt(progname, argc, argv);
#endif // INCLUDE_SRTP
    } else if (0 == strcasecmp(action, ARG_ACT_STATS)) {
        return run_stats(progname, argc, argv);
    }

    fprintf(stdout, "%s: unhandled action='%s'\n", progname, action);
    return -4;
}
