#pragma once

namespace CLI {
class App;
}

void add_details_command(CLI::App &parent, int &exit_code, const char *progname);
