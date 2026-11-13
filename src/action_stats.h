#pragma once

namespace CLI {
class App;
}

void add_stats_command(CLI::App &parent, int &exit_code, const char *progname);
