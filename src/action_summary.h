#pragma once

namespace CLI {
class App;
}

void add_summary_command(CLI::App &parent, int &exit_code, const char *progname);
