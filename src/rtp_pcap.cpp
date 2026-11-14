#include <string.h> // for strrchr()

#include <CLI/CLI.hpp>
#include <iostream>
#include <string>
#include <vector>

#include "action_details.h"
#include "action_list.h"
#if INCLUDE_SRTP
#include "action_srtp.h"
#endif // INCLUDE_SRTP
#include "action_stats.h"
#include "action_summary.h"

// A bare action (rtp-pcap details) has no flags yet. Required options are checked
// during parse, so print that action's usage first and leave the process status at 0.
static bool usage_for_bare_action(CLI::App &app, const char *action) {
    std::vector<CLI::App *> subs = app.get_subcommands([](CLI::App *) { return true; });
    for (std::size_t i = 0; i < subs.size(); i++) {
        if (subs[i]->check_name(action)) {
            std::cout << subs[i]->help(app.get_name());
            return true;
        }
    }
    return false;
}

int rtp_pcap_run(int argc, char *argv[]) {
    const char *slash = strrchr(argv[0], '/');
    const char *progname = (NULL == slash ? argv[0] : slash + 1);
    int exit_code = 0;

    CLI::App app{"Look at RTP in a PCAP file"};
    app.name(progname);
    app.ignore_case();
    app.option_defaults()->ignore_case();
    app.set_help_flag("-h,--help", "Print this help message and exit");
    app.require_subcommand();

    add_list_command(app, exit_code, progname);
    add_summary_command(app, exit_code, progname);
    add_details_command(app, exit_code, progname);
    add_stats_command(app, exit_code, progname);
#if INCLUDE_SRTP
    add_encrypt_command(app, exit_code, progname);
    add_decrypt_command(app, exit_code, progname);
#endif // INCLUDE_SRTP

    app.footer(std::string("Use \"") + progname + " <action> --help\" for action argument info.");

    if (argc <= 1) {
        std::cout << app.help();
        return 0;
    }
    if (argc == 2 && usage_for_bare_action(app, argv[1])) {
        return 0;
    }

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError &e) {
        return app.exit(e);
    }
    return exit_code;
}
