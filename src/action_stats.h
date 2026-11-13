#pragma once

namespace CLI {
class App;
}

void add_stats_command(CLI::App &app, int &exit_code, const char *progname);
